module Analysis (informationFlowAnalysis) where

import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.List (find)

import Data.Graph.Dom as Dom

import Types
import Ebpf.Asm

-- Perform a the information flow analysis on a set of equations.
informationFlowAnalysis :: Dom.Rooted -> Equations -> State -> SystemState
informationFlowAnalysis graph eq initialState =
  fixpointComputation graph (replicate ((length eq) + 1) initialState, Low, Set.empty) (Map.toList eq)

-- Perform fixpoint computation for the analysis.
fixpointComputation :: Dom.Rooted -> SystemState -> [(Label, [(Label, Stmt)])] -> SystemState 
fixpointComputation graph ss eq = 
  if ss == ss'
    then ss'
    else fixpointComputation graph ss' eq
      where 
        ss' = foldl (updateSystemState graph) ss eq

-- This function updates the System state with a new state for the node being processed.
updateSystemState :: Dom.Rooted -> SystemState -> (Label, [(Label, Stmt)]) -> SystemState
updateSystemState graph (states, mem, highContext) (nodeIdx, eqs) = 
  (before ++ [state'] ++ after, mem', highContext')
  where
    startState = states !! nodeIdx
    (state', mem', highContext') = processElement graph startState (states, mem, highContext) (nodeIdx, eqs)
    before = take nodeIdx states 
    after = drop (nodeIdx + 1) states
    
-- Processes the equations for a specific node, returning the updated state.     
processElement :: Dom.Rooted -> State -> SystemState -> (Label, [(Label, Stmt)]) -> (State, Memory, HighSecurityContext)
processElement _ state (_, m, j) (_,[]) = (state, m, j)
processElement graph state (states, mem, highContext) (currentNode, ((prevNode, stmt):es)) = otherState
  where 
    dependsOnJump = isInHighContext prevNode (Set.toList highContext)
    prevState = (states !! prevNode)
    (state',  mem', highContext') = updateUsingStmt graph prevState mem highContext dependsOnJump (prevNode, currentNode) stmt 
    newState = unionStt state state'
    otherState = processElement graph newState (states,  mem', highContext') (currentNode, es)

-- TODO
-- Update a node's state by analysing the security level of an equation, it also updates the context if the equation 
-- is a conditional jump, i.e. if cond.
updateUsingStmt :: Dom.Rooted -> State -> Memory -> HighSecurityContext -> Bool -> (Int,Int) -> Stmt -> (State, Memory, HighSecurityContext)
updateUsingStmt _ state mem highContext dependsOnJump _ (AssignReg r e) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (updatedState, mem, highContext)
  where 
    secLevel = 
      if dependsOnJump 
        then High 
        else processBinaryOp state e
    updatedState = updateRegisterSecurity r secLevel state
updateUsingStmt _ state mem highContext dependsOnJump _ (AssignMem r e) = 
  case lookup r state of 
    Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
    _ -> (state, mem', highContext)
  where
    secLevel = 
      if dependsOnJump 
        then High 
        else processBinaryOp state e
    mem' = if mem == High then High else secLevel
updateUsingStmt graph state mem highContext dependsOnJump (prevNode, _) (If cond _) =  
  if secLevelCond == High || dependsOnJump 
    then 
      case find (\(n,_) -> n == prevNode) (ipdom graph) of
        Just (_, nodePD) -> 
          (state, mem, Set.insert (prevNode, (highContextNodes prevNode nodePD graph)) highContext)
        Nothing -> (state, mem, highContext)
    else (state, mem, highContext)
  where
    (r, ri) = extractFromCond cond
    secLevelExp1 = processBinaryOp state r
    secLevelExp2 = processBinaryOp state ri
    secLevelCond = if secLevelExp1 == Low && secLevelExp2 == Low then Low else High
updateUsingStmt _ state mem highContext _ _ (Goto _) = (state, mem, highContext)  


------------------- Functions related to processing different Stmt ------------------------

-- Process an expression, returning the security level of the expression.
processBinaryOp :: State -> BinaryOp -> SecurityLevel
processBinaryOp state  e = 
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
    ArshOp r ri  -> getBinOpSecurityLvl state r ri
    MovOp ri -> case ri of 
      R r' -> getRegisterSecurityLevel state r'
      Imm _ -> Low

-- Extract the two expressions used in a Condition.
extractFromCond :: Cond -> (Reg, RegImm)
extractFromCond (Equal r ri)      = (r, ri)
extractFromCond (NotEqual r ri)   = (r, ri)
extractFromCond (LessThan r ri)   = (r, ri)
extractFromCond (LessEqual r ri)  = (r, ri)
extractFromCond (GreaterThan r ri)  = (r, ri) 
extractFromCond (GreaterEqual r ri) = (r, ri)

------------------- Functions related to states handling ------------------------

-- Processes a binary operation by processing both expressions, returning the higher security level of both.
getBinOpSecurityLvl :: State -> Reg -> RegImm -> SecurityLevel
getBinOpSecurityLvl state r ri = if sec1 == High || sec2 == High then High else Low
  where
    sec1 = getRegisterSecurityLevel state r
    sec2 = case ri of 
      R r' -> getRegisterSecurityLevel state r'
      Imm _ -> Low

-- Get the register sec level from the state
getRegisterSecurityLevel :: State -> Reg -> SecurityLevel
getRegisterSecurityLevel state r = case lookup r state of
  Just s -> s
  Nothing -> error ("Not defined register: " ++ show r)

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
