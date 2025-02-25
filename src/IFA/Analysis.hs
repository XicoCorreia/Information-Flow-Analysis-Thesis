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

-- This function updates the System state with a new state for the node being processed.
updateSystemState :: Dom.Rooted -> SystemState -> (Label, [(Label, Stmt)]) -> SystemState
updateSystemState graph (states, mem, highContext) (nodeIdx, eqs) = 
  (before ++ [state'] ++ after, mem', highContext')
  where
    (state', mem', highContext') = processElement graph Nothing (states, mem, highContext) (nodeIdx, eqs)
    before = take nodeIdx states 
    after = drop (nodeIdx + 1) states
    
-- Processes the equations for a specific node, returning the updated state.     
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
-- is a conditional jump, i.e. if cond.
updateUsingStmt :: Dom.Rooted -> State -> Memory -> HighSecurityContext -> Bool -> (Int,Int) -> Stmt -> (State, Memory, HighSecurityContext)
-- Process Binary operations
updateUsingStmt _ state mem highContext inHighContext _ (AssignReg r (Bin e)) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = if inHighContext then High else processBinaryOp state e
    updatedState = updateRegisterSecurity r secLevel state

-- Process Unary operations
updateUsingStmt _ state mem highContext inHighContext _ (AssignReg r (Un e)) = 
    case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = if inHighContext then High else processUnaryOp state e
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
    mem' = if mem == High then High else secLevel

-- Process Load operation with register as index
updateUsingStmt _ state mem highContext inHighContext _ (LoadFromMemReg r r' _) =
    case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> case lookup r' state of 
            Nothing -> error ("Register: " ++ show r' ++ " is not allowed to be used")
            _ -> (updatedState, mem, highContext)
  where
    secLevelIdx = if inHighContext then High else getRegisterSecurityLevel state r'
    secLevel = if mem == High then High else secLevelIdx
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
  if secLevelCond == High || inHighContext 
    then 
      case find (\(n,_) -> n == prevNode) (ipdom graph) of
        Just (_, nodePD) -> 
          (state, mem, Set.insert (prevNode, (highContextNodes prevNode nodePD graph)) highContext)
        Nothing -> (state, mem, highContext)
    else (state, mem, highContext)
  where
    (r, ri) = extractFromCond cond
    secLevelExp1 = getRegisterSecurityLevel state r
    secLevelExp2 = getRegisterImmSecurityLevel state ri
    secLevelCond = if secLevelExp1 == Low && secLevelExp2 == Low then Low else High

-- Process Unconditional jump
updateUsingStmt _ state mem highContext _ _ (Goto _) = (state, mem, highContext) 

-- Process Call operation
updateUsingStmt _ state mem highContext _ _ (CallOp _) = (state, mem, highContext)   

------------------- Functions related to processing different Stmt ------------------------

-- Process an expression, returning the security level of the expression.
processBinaryOp :: State -> BinaryOp -> SecurityLevel
processBinaryOp state e = 
  case e of 
    AddOp r ri -> getBinOpSecurityLvl state r ri
    SubOp r ri -> getBinOpSecurityLvl state r ri
    MulOp r ri -> getBinOpSecurityLvl state r ri
    DivOp r ri -> getBinOpSecurityLvl state r ri
    OrOp  r ri -> getBinOpSecurityLvl state r ri
    AndOp r ri -> getBinOpSecurityLvl state r ri
    LshOp r ri -> getBinOpSecurityLvl state r ri
    RshOp r ri -> getBinOpSecurityLvl state r ri
    ModOp r ri -> getBinOpSecurityLvl state r ri
    XorOp r ri -> getBinOpSecurityLvl state r ri
    ArshOp r ri -> getBinOpSecurityLvl state r ri

processUnaryOp :: State -> UnaryOp -> SecurityLevel
processUnaryOp state e = 
  case e of 
    NegOp r -> getRegisterSecurityLevel state r 
    LeOp r -> getRegisterSecurityLevel state r 
    BeOp r -> getRegisterSecurityLevel state r 

-- Extract the two expressions used in a Condition.
extractFromCond :: Condition -> (Reg, RegImm)
extractFromCond (Equal r ri)        = (r, ri)
extractFromCond (NotEqual r ri)     = (r, ri)
extractFromCond (LessThan r ri)     = (r, ri)
extractFromCond (LessEqual r ri)    = (r, ri)
extractFromCond (GreaterThan r ri)  = (r, ri) 
extractFromCond (GreaterEqual r ri) = (r, ri)

------------------- Functions related to states handling ------------------------

-- Processes a binary operation by processing both expressions, returning the higher security level of both.
getBinOpSecurityLvl :: State -> Reg -> RegImm -> SecurityLevel
getBinOpSecurityLvl state r ri = if sec1 == High || sec2 == High then High else Low
  where
    sec1 = getRegisterSecurityLevel state r
    sec2 = getRegisterImmSecurityLevel state ri

-- Get the register sec level from the state
getRegisterImmSecurityLevel :: State -> RegImm -> SecurityLevel
getRegisterImmSecurityLevel state ri = case ri of 
      R r' -> getRegisterSecurityLevel state r'
      Imm _ -> Low

-- Get the register sec level from the state
getRegisterSecurityLevel :: State -> Reg -> SecurityLevel
getRegisterSecurityLevel state r = case lookup r state of
  Just s -> s
  Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")

-- Update the register security in a state.
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
