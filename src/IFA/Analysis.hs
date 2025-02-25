module IFA.Analysis (informationFlowAnalysis) where

import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.List (find)

import Data.Graph.Dom as Dom

import IFA.Types
import Ebpf.Asm

------------------- Functions that perform the analysis at each program point ------------------------

-- Perform a the information flow analysis on a set of equations.
informationFlowAnalysis :: Dom.Rooted -> Equations -> State -> SystemState
informationFlowAnalysis graph eq initialState =
  fixpointComputation graph (replicate ((length eq) + 1) initialState, Low, Set.empty) (Map.toList eq)

-- Perform fixpoint computation for the analysis.
fixpointComputation :: Dom.Rooted -> SystemState -> [(Label, [(Label, Stmt)])] -> SystemState 
fixpointComputation graph ss eq = 
  if ss == ss' then ss' else fixpointComputation graph ss' eq
  where 
    ss' = foldl (updateSystemState graph) ss eq

-- This function updates the System state with the updated state for the node being processed.
updateSystemState :: Dom.Rooted -> SystemState -> (Label, [(Label, Stmt)]) -> SystemState
updateSystemState graph (states, mem, highContext) (nodeIdx, eqs) = 
  (before ++ [state'] ++ after, mem', highContext')
  where
    (state', mem', highContext') = processElement graph Nothing (states, mem, highContext) (nodeIdx, eqs)
    before = take nodeIdx states 
    after = drop (nodeIdx + 1) states
    
-- Process the equations for a specific node, returning the updated SystemState.     
processElement :: Dom.Rooted -> Maybe State -> SystemState -> (Label, [(Label, Stmt)]) -> (State, Memory, HighSecurityContext)
processElement _ (Nothing) (states, mem, highContext) (nodeIdx,[]) = ((states !! nodeIdx), mem, highContext)
processElement _ (Just state) (_, mem, highContext) (_,[]) = (state, mem, highContext)
processElement graph unionState (states, mem, highContext) (currentNode, ((prevNode, stmt):es)) =     
  case unionState of
      Nothing -> processElement graph (Just state) (states,  mem', highContext') (currentNode, es)
      Just uState -> processElement graph (Just (unionStt uState state)) (states,  mem', highContext') (currentNode, es)
  where 
    inHighContext = isInHighContext prevNode (Set.toList highContext)
    prevState = (states !! prevNode)
    (state,  mem', highContext') = updateUsingStmt graph prevState mem highContext inHighContext (prevNode, currentNode) stmt 

-- Update a node's state by analysing the security level of an equation, it also updates the context if the equation 
-- is a conditional jump, i.e. if cond, and in case it is a Store operation updates the memory.
updateUsingStmt :: Dom.Rooted -> State -> Memory -> HighSecurityContext -> Bool -> (Int,Int) -> Stmt -> (State, Memory, HighSecurityContext)

-- Process Binary operations
updateUsingStmt _ state mem highContext inHighContext _ (AssignReg r (Bin e)) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = if inHighContext then High else processBinaryExp state e
    updatedState = updateRegisterSecurity r secLevel state

-- Process Unary operations
updateUsingStmt _ state mem highContext inHighContext _ (AssignReg r (Un e)) = 
    case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = if inHighContext then High else processUnaryExp state e
    updatedState = updateRegisterSecurity r secLevel state

-- Process Mov operation
updateUsingStmt _ state mem highContext inHighContext _ (AssignReg r (Mv ri)) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = if inHighContext then High else getRegisterImmSecurityLevel state ri
    updatedState = updateRegisterSecurity r secLevel state

-- Process Store operations
updateUsingStmt _ state mem highContext inHighContext _ (StoreInMem r _ ri) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (state, mem', highContext)
  where
    secLevelIdx = if inHighContext then High else getRegisterSecurityLevel state r
    secLevel = if secLevelIdx == High then High else getRegisterImmSecurityLevel state ri
    mem' = if secLevel == High then High else mem

-- Process Load operation with register as index
updateUsingStmt _ state mem highContext inHighContext _ (LoadFromMemReg r r' _) =
    case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> case lookup r' state of 
            Nothing -> error ("Register: " ++ show r' ++ " is not allowed to be used")
            _ -> (updatedState, mem, highContext)
  where
    secLevelIdx = if inHighContext then High else getRegisterSecurityLevel state r'
    secLevel = if secLevelIdx == High then High else mem
    updatedState = updateRegisterSecurity r secLevel state

-- Process Load operation with Imm as index
updateUsingStmt _ state mem highContext inHighContext _ (LoadFromMemImm r _) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where
    secLevel = if inHighContext then High else mem
    updatedState = updateRegisterSecurity r secLevel state

-- Process conditional jumps
updateUsingStmt graph state mem highContext inHighContext (prevNode, _) (If cond _) =  
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
updateUsingStmt _ state mem highContext _ _ (Goto _) = (state, mem, highContext) 

-- Process Call operation
updateUsingStmt _ state mem highContext _ _ (CallOp _) = (state, mem, highContext)   

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
