module IFA.Analysis (informationFlowAnalysis) where

import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.List (find, foldl')

import Data.Graph.Dom as Dom

import IFA.Types
import Ebpf.Asm

------------------- Functions that perform the analysis at each program point ------------------------

defaultState :: State
defaultState = [
    (Reg 0, Low), (Reg 1, Low), (Reg 2, Low), 
    (Reg 3, Low), (Reg 4, Low), (Reg 5, Low), 
    (Reg 6, Low), (Reg 7, Low), (Reg 8, Low), 
    (Reg 9, Low), (Reg 10, Low)]

-- Given a starting state with the security level for each register,
-- perform the information flow analysis on a set of equations.
informationFlowAnalysis :: Dom.Rooted -> Equations -> State -> [ItvState] -> SystemState
informationFlowAnalysis graph eq initialState itvStates =
  fixpointComputation graph itvStates (initialState : replicate (length eq) defaultState, Map.fromList [(i, Low) | i <- [0..511]] , Set.empty) (Map.toList eq) 

-- Perform fixpoint computation for the analysis.
fixpointComputation :: Dom.Rooted -> [ItvState] -> SystemState -> [(Label, [(Label, Stmt)])] -> SystemState 
fixpointComputation graph itvStates (s,m,c) eq = 
  -- seq is used to force evaluation of the memory to catch errors
  m' `seq` if s == s' then (s',m',c') else fixpointComputation graph itvStates (s',m,c') eq
  where 
    (s',m',c') = foldl (updateSystemState graph itvStates) (s,m,c) eq

-- This function updates the System state with the updated state for the node being processed.
updateSystemState :: Dom.Rooted -> [ItvState] -> SystemState -> (Label, [(Label, Stmt)]) -> SystemState
updateSystemState graph itvStates (states, mem, highContext) (nodeIdx, eqs) = 
  (before ++ [state'] ++ after, mem', highContext')
  where
    (state', mem', highContext') = processElement graph itvStates Nothing (states, mem, highContext) (nodeIdx, eqs)
    before = take nodeIdx states 
    after = drop (nodeIdx + 1) states
    
-- Process the equations for a specific node, returning the updated SystemState.     
processElement :: Dom.Rooted -> [ItvState] -> Maybe State -> SystemState -> (Label, [(Label, Stmt)]) -> (State, Memory, HighSecurityContext)
processElement _ _ (Nothing) (states, mem, highContext) (nodeIdx,[]) = ((states !! nodeIdx), mem, highContext)
processElement _ _ (Just state) (_, mem, highContext) (_,[]) = (state, mem, highContext)
processElement graph itvState unionState (states, mem, highContext) (currentNode, ((prevNode, stmt):es)) =     
  case unionState of
      Nothing -> processElement graph itvState (Just state) (states,  mem', highContext') (currentNode, es)
      Just uState -> processElement graph itvState (Just (unionStt uState state)) (states,  mem', highContext') (currentNode, es)
  where 
    inHighContext = isInHighContext prevNode (Set.toList highContext)
    prevState = (states !! prevNode)
    itv = (itvState !! prevNode)
    (state,  mem', highContext') = updateUsingStmt graph itv prevState mem highContext inHighContext (prevNode, currentNode) stmt 

-- Update a node's state by analysing the security level of an equation, it also updates the context if the equation 
-- is a conditional jump, i.e. if cond, and in case it is a memory handling operation updates the memory.
updateUsingStmt :: Dom.Rooted -> ItvState -> State -> Memory -> HighSecurityContext -> Bool -> (Int,Int) -> Stmt -> (State, Memory, HighSecurityContext)

-- Process Binary operations
updateUsingStmt _ _ state mem highContext inHighContext _ (AssignReg r (Bin e)) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = if inHighContext then High else processBinaryExp state e
    updatedState = updateRegisterSecurity r secLevel state

-- Process Unary operations
updateUsingStmt _ _ state mem highContext inHighContext _ (AssignReg r (Un e)) = 
    case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = if inHighContext then High else processUnaryExp state e
    updatedState = updateRegisterSecurity r secLevel state

-- Process Mov operation
updateUsingStmt _ _ state mem highContext inHighContext _ (AssignReg r (Mv ri)) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = if inHighContext then High else getRegisterImmSecurityLevel state ri
    updatedState = updateRegisterSecurity r secLevel state

-- Process Store operations
updateUsingStmt _ itvState state mem highContext inHighContext _ (StoreInMem r off ri) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (state, mem', highContext)
  where
    secLevelIdx = if inHighContext then High else getRegisterSecurityLevel state r
    secLevel' = if secLevelIdx == High then High else getRegisterImmSecurityLevel state ri
    secLevel = if secLevel' == High then High else getMemorySecurityLevel mem itvState (R r) off
    mem' = updateMemorySecurity mem itvState r off secLevel 

-- Process Load operation with register as index
updateUsingStmt _ itvState state mem highContext inHighContext _ (LoadFromMemReg r r' off) =
    case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> case lookup r' state of 
            Nothing -> error ("Register: " ++ show r' ++ " is not allowed to be used")
            _ -> (updatedState, mem, highContext)
  where
    secLevelIdx = if inHighContext then High else getRegisterSecurityLevel state r'
    secLevel = if secLevelIdx == High then High else getMemorySecurityLevel mem itvState (R r') off
    updatedState = updateRegisterSecurity r secLevel state

-- Process Load operation with Imm as index
updateUsingStmt _ itvState state mem highContext inHighContext _ (LoadFromMemImm r i) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where
    secLevel = if inHighContext then High else getMemorySecurityLevel mem itvState (Imm i) Nothing 
    updatedState = updateRegisterSecurity r secLevel state

-- Process conditional jumps
updateUsingStmt graph  _ state mem highContext inHighContext (prevNode, _) (If cond _) =  
  if secLevel == High
    then 
      case find (\(n,_) -> n == prevNode) (ipdom graph) of
        Just (_, nodePD) -> 
          (state, mem, Set.insert (prevNode, (highContextNodes prevNode nodePD graph)) highContext)
        Nothing -> (state, mem, highContext)
    else (state, mem, highContext)
  where
    secLevel = if inHighContext then High else processCondition state cond

-- Process Unconditional jump
updateUsingStmt _ _ state mem highContext _ _ (Goto _) = (state, mem, highContext) 

-- Process Call operation
updateUsingStmt _ _ state mem highContext _ _ (CallOp _) = (state, mem, highContext)   

------------------- Functions related to processing different Stmt ------------------------

-- Process a binary expression, returning the security level of the expression.
processBinaryExp :: State -> BinaryExp -> SecurityLevel
processBinaryExp state e = 
  case e of 
    AddOp r ri -> getBinaryExpSecurityLevel state r ri
    SubOp r ri -> getBinaryExpSecurityLevel state r ri
    MulOp r ri -> getBinaryExpSecurityLevel state r ri
    DivOp r ri -> getBinaryExpSecurityLevel state r ri
    OrOp  r ri -> getBinaryExpSecurityLevel state r ri
    AndOp r ri -> getBinaryExpSecurityLevel state r ri
    LshOp r ri -> getBinaryExpSecurityLevel state r ri
    RshOp r ri -> getBinaryExpSecurityLevel state r ri
    ModOp r ri -> getBinaryExpSecurityLevel state r ri
    XorOp r ri -> getBinaryExpSecurityLevel state r ri
    ArshOp r ri -> getBinaryExpSecurityLevel state r ri

-- Process an unary expression, returning the security level of the expression.
processUnaryExp :: State -> UnaryExp -> SecurityLevel
processUnaryExp state e = 
  case e of 
    NegOp r -> getRegisterSecurityLevel state r 
    LeOp r -> getRegisterSecurityLevel state r 
    BeOp r -> getRegisterSecurityLevel state r 

-- Process a Condition, returning the security level of the condition.
processCondition :: State -> Condition -> SecurityLevel
processCondition state e = 
  case e of 
    Equal r ri -> getBinaryExpSecurityLevel state r ri
    NotEqual r ri -> getBinaryExpSecurityLevel state r ri
    LessThan r ri -> getBinaryExpSecurityLevel state r ri
    LessEqual r ri -> getBinaryExpSecurityLevel state r ri
    GreaterThan r ri -> getBinaryExpSecurityLevel state r ri
    GreaterEqual r ri -> getBinaryExpSecurityLevel state r ri

------------------- Functions related to states handling ------------------------

-- Process a binary operation by processing the register and register or Immediate, 
-- returning the higher security level of both.
getBinaryExpSecurityLevel :: State -> Reg -> RegImm -> SecurityLevel
getBinaryExpSecurityLevel state r ri = if sec1 == High || sec2 == High then High else Low
  where
    sec1 = getRegisterSecurityLevel state r
    sec2 = getRegisterImmSecurityLevel state ri

-- Get the register or Immmediate security level.
getRegisterImmSecurityLevel :: State -> RegImm -> SecurityLevel
getRegisterImmSecurityLevel state ri = case ri of 
      R r' -> getRegisterSecurityLevel state r'
      Imm _ -> Low

-- Get the register security level from the state.
getRegisterSecurityLevel :: State -> Reg -> SecurityLevel
getRegisterSecurityLevel state r = case lookup r state of
  Just s -> s
  Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")

-- Update the register security level in a state.
updateRegisterSecurity :: Reg -> SecurityLevel -> State -> State
updateRegisterSecurity r secLevel = map (\(reg, sec) -> 
    if reg == r 
        then (reg, secLevel)
        else (reg, sec))

-- Given a register as index the function gets the possible values for the index from the interval
-- state and for each of the possible index update the memory cell with the security level
updateMemorySecurity :: Memory -> ItvState -> Reg -> Maybe MemoryOffset -> SecurityLevel -> Memory
updateMemorySecurity mem itvState r off seclvl = 
  case lookup r itvState of
    Just itv -> foldl' (\m idx -> Map.insert idx seclvl m) mem indices
      where 
        offset = case off of
          Nothing -> 0
          Just o -> o
        indices = fixInterval itv (fromIntegral offset)
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")

-- In case the RegImm is an immediate it returns the security level of that memory cell,
-- if the index is a register, it becomes an interval, so the security level returned is
-- the LUB for all the possible indices
getMemorySecurityLevel :: Memory -> ItvState -> RegImm -> Maybe MemoryOffset -> SecurityLevel
getMemorySecurityLevel mem _ (Imm i) _ = 
  case Map.lookup (fromIntegral  i) mem of
    Just s -> s
    Nothing -> error "Unaccessable memory"
getMemorySecurityLevel mem itvState (R r) off = 
  case lookup r itvState of
    Just itv -> if isHigh then High else Low
      where 
        offset = case off of
          Nothing -> 0
          Just o -> o
        indices = fixInterval itv (fromIntegral offset)
        isHigh = any (\i -> Map.lookup i mem == Just High) indices
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
  
-- Takes the interval of possible indexes and returns a list of ints with the
-- possible indexes, taking into account that the memory has 512 cells
fixInterval :: Itv -> Int -> [Int]
fixInterval (Itv (NegInfinity, PosInfinity)) _ = [0..511]
fixInterval (Itv (NegInfinity, Finite x)) off = [0..maxV]
  where
    x' = x + off
    maxV = if x' >= 511 then 511 else 
          if x' >= 0 then x' else error "Memory index is not valid" 
fixInterval (Itv (Finite x, PosInfinity)) off = [minV..511]
  where
    x' = x + off
    minV = if x' <= 0 then 0 else 
          if x' <= 511 then x' else error "Memory index is not valid" 
fixInterval (Itv (Finite x, Finite y)) off = [minV..maxV]
  where
    x' = x + off
    minV = if x' <= 0 then 0 else 
          if x' <= 511 then x' else error "Memory index is not valid" 
    y' = y + off
    maxV = if y' >= 511 then 511 else 
          if y' >= 0 then y' else error "Memory index is not valid" 
fixInterval EmptyItv _ = []
fixInterval _ _ = error "Interval needs to be normalized"

-- Union of two states.
unionStt :: State -> State -> State
unionStt = zipWith combine
  where
    combine (reg, sec1) (_, sec2) = (reg, if sec1 == High || sec2 == High then High else Low)

------------------- Functions related to High Context ------------------------

-- Verify if node is in a High context.
isInHighContext :: Label -> [(Label, [Label])] -> Bool
isInHighContext _ [] = False
isInHighContext prevNode ((_,nodes):xs) = 
  if prevNode `elem` nodes 
    then True 
    else isInHighContext prevNode xs

-- Returns the nodes that belong to the high security context starting in the node
-- containing the jump and ending in the immediate post dominator of that node.
highContextNodes :: Label -> Label -> Dom.Rooted -> [Label]
highContextNodes node nodePD graph = Set.toList $ Set.delete node res
  where res = Set.fromList (concat $ highContextNodes' node nodePD graph Set.empty)

-- Helper function that performs the logic to calculate the nodes inside the high security context
highContextNodes' :: Label -> Label -> Dom.Rooted -> Set.Set Label -> [[Label]]
highContextNodes' start end (root,cfg) visited
    | start == end = [[]] -- Base case: Path ends when start equals end
    | start `Set.member` visited = [[]] -- Node already visited, avoid loops
    | otherwise = [if neighbor == end then [] else neighbor : path | 
      neighbor <- neighbors, path <- highContextNodes' neighbor end (root,cfg) (Set.insert start visited)]
        where neighbors = graphSucc start (toEdges cfg)

-- Get successors (neighbors) of a node
graphSucc :: Label -> [Edge] -> [Label]
graphSucc node cfg = [to | (from, to) <- cfg, from == node]
