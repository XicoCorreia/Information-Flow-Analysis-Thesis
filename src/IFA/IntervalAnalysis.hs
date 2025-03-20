module IFA.IntervalAnalysis (intervalAnalysis) where

import qualified Data.Map as Map

import IFA.Types
import Ebpf.Asm

------------------- Interval Analysis Types ------------------------
-- Represents the possible values in an interval.
data IntVal = 
    Finite Int
  | NegInfinity
  | PosInfinity
    deriving (Show)

instance Eq IntVal where
  (Finite x) == (Finite y)       = x == y
  NegInfinity == NegInfinity     = True
  PosInfinity == PosInfinity     = True
  _ == _                         = False

instance Ord IntVal where
  compare (Finite x) (Finite y)       = compare x y
  compare (Finite _) NegInfinity      = GT
  compare (Finite _) PosInfinity      = LT
  compare NegInfinity (Finite _)      = LT
  compare NegInfinity NegInfinity     = EQ
  compare NegInfinity PosInfinity     = LT
  compare PosInfinity (Finite _)      = GT
  compare PosInfinity NegInfinity     = GT
  compare PosInfinity PosInfinity     = EQ

-- Interval, can be empty if not initialized.
data Interval = 
    Itv (IntVal, IntVal)
  | EmptyItv
    deriving (Show, Eq)

------------------- Interval Operations ------------------------

-- Perform the union of two intervals.
unionInterval :: Interval -> Interval -> Interval
unionInterval EmptyItv x = x
unionInterval x EmptyItv = x
-- case (-inf, +inf) \/ ...
unionInterval (Itv (NegInfinity, PosInfinity)) _ = Itv (NegInfinity, PosInfinity)  
-- case (-inf,x) \/ ...
unionInterval (Itv (NegInfinity, Finite _)) (Itv (_, PosInfinity)) = Itv (NegInfinity, PosInfinity)
unionInterval (Itv (NegInfinity, Finite x)) (Itv (_, Finite y)) = Itv (NegInfinity, Finite (max x y))
-- case (x,+inf) \/ ...
unionInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, _)) = Itv (Finite (min x1 y1), PosInfinity)
unionInterval (Itv (Finite _, PosInfinity)) (Itv (NegInfinity, _)) = Itv (NegInfinity, PosInfinity)
-- case (x1, x2) \/ ...
unionInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (min x1 y1), Finite (max x2 y2))
unionInterval (Itv (Finite _, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (max x2 y2))
unionInterval (Itv (Finite x1, Finite _)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (min x1 y1), PosInfinity)
unionInterval (Itv (Finite _, Finite _)) (Itv (NegInfinity, PosInfinity)) = Itv (NegInfinity, PosInfinity)  
-- case when one of the intervals is not correctly formatted
unionInterval x y = unionInterval (normalizeInterval x) (normalizeInterval y)

-- Perform the intersection of two intervals.
intersectionInterval :: Interval -> Interval -> Interval
intersectionInterval EmptyItv _ = EmptyItv
intersectionInterval _ EmptyItv = EmptyItv
-- case (-inf, +inf) /\ ...
intersectionInterval (Itv (NegInfinity, PosInfinity)) x = x
intersectionInterval x (Itv (NegInfinity, PosInfinity)) = x
-- case (-inf,x) /\ ...
intersectionInterval (Itv (NegInfinity, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (min x2 y2))
intersectionInterval (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (Finite y1, Finite x2)
intersectionInterval (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite y1, Finite (min x2 y2))
-- case (x,+inf) /\ ...
intersectionInterval (Itv (Finite x1, PosInfinity)) (Itv (NegInfinity, Finite y2)) = Itv (Finite x1, Finite y2)
intersectionInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (max x1 y1), PosInfinity)
intersectionInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, Finite y2)) = Itv (Finite (max x1 y1), Finite y2)
-- case (x1,x2) /\ ...
intersectionInterval (Itv (Finite x1, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (Finite x1, Finite (min x2 y2))
intersectionInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (max x1 y1), Finite x2)
intersectionInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (max x1 y1), Finite (min x2 y2))
-- case when one of the intervals is not correctly formatted
intersectionInterval x y = intersectionInterval (normalizeInterval x) (normalizeInterval y)

-- Normalize the interval, i.e. correct the intervals in case of bad formatting.
normalizeInterval :: Interval -> Interval
normalizeInterval  (Itv (Finite x1, Finite x2)) = 
  if x1 <= x2 
    then (Itv (Finite x1, Finite x2)) 
    else EmptyItv
normalizeInterval  (Itv (_, NegInfinity)) = EmptyItv
normalizeInterval  (Itv (PosInfinity, _)) = EmptyItv
normalizeInterval x = x

-- Takes an int n and returns the constant as an interval [n,n].
constantInterval :: Int -> Interval
constantInterval x = (Itv (Finite x, Finite x)) 

------------------- Arithmetic Interval Operations ------------------------

-- TODO
addInterval :: Interval -> Interval -> Interval
addInterval (Itv (NegInfinity, PosInfinity)) _ = Itv (NegInfinity, PosInfinity)
addInterval _ (Itv (NegInfinity, PosInfinity)) = Itv (NegInfinity, PosInfinity)
addInterval EmptyItv _ = EmptyItv
addInterval _ EmptyItv = EmptyItv
addInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (x1 + y1), Finite (x2 + y2))
addInterval (Itv (_, Finite x2)) (Itv (_, Finite y2)) = Itv (NegInfinity, Finite (x2 + y2))
addInterval (Itv (Finite x1, _)) (Itv (Finite y1, _)) = Itv (Finite (x1 + y1), PosInfinity)
addInterval (Itv (_, PosInfinity)) (Itv (NegInfinity, _))  = Itv (NegInfinity, PosInfinity)
addInterval (Itv (NegInfinity, _)) (Itv (_, PosInfinity)) = Itv (NegInfinity, PosInfinity)
-- case when one of the intervals is not correctly formatted
addInterval x y = addInterval (normalizeInterval x) (normalizeInterval y)

-- TODO
subInterval :: Interval -> Interval -> Interval
subInterval (Itv (NegInfinity, PosInfinity)) _ = Itv (NegInfinity, PosInfinity)
subInterval _ (Itv (NegInfinity, PosInfinity)) = Itv (NegInfinity, PosInfinity)
subInterval EmptyItv _ = EmptyItv
subInterval _ EmptyItv = EmptyItv
subInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (x1 - y2), Finite (x2 - y1))
subInterval (Itv (_, Finite x2)) (Itv (Finite y1, _)) = Itv (NegInfinity, Finite (x2 - y1))
subInterval (Itv (Finite x1, _)) (Itv (_, Finite y2)) = Itv (Finite (x1 - y2), PosInfinity)
subInterval (Itv (NegInfinity, _)) (Itv (NegInfinity, _)) = Itv (NegInfinity, PosInfinity)
subInterval (Itv (_, PosInfinity)) (Itv (_, PosInfinity)) = Itv (NegInfinity, PosInfinity)
-- case when one of the intervals is not correctly formatted
subInterval x y = subInterval (normalizeInterval x) (normalizeInterval y)

------------------- Logical Interval Operations ------------------------

-- Equal operation [=] ([a,b],[c,d]) = ([a,b] /\ [c,d], [a,b] /\ [c,d]).
eqInterval :: Interval -> Interval -> (Interval, Interval)
eqInterval x y = (intersectionInterval x y, intersectionInterval x y)

-- Less than operation [<] ([a,b],[c,d]) = ([a,b] /\ [-inf, d-1], [a+1,+inf] /\ [c,d]).
ltInterval :: Interval -> Interval -> (Interval, Interval)
ltInterval EmptyItv _ = (EmptyItv, EmptyItv)
ltInterval _ EmptyItv = (EmptyItv, EmptyItv)
-- case (x1,_) < (_,y1)
ltInterval (Itv (Finite x1,x2)) (Itv (y1,Finite y2)) = 
  (intersectionInterval (Itv (Finite x1, x2)) (Itv (NegInfinity, Finite (y2-1))),
   intersectionInterval (Itv (Finite (x1 + 1), PosInfinity)) (Itv (y1, Finite y2)))
-- case (x1,_) < (_,+inf) 
ltInterval (Itv (Finite x1,x2)) (Itv (y1,PosInfinity)) = 
  (intersectionInterval (Itv (Finite x1, x2)) (Itv (NegInfinity, PosInfinity)),
   intersectionInterval (Itv (Finite (x1 + 1), PosInfinity)) (Itv (y1, PosInfinity)))
-- case (-inf,_) < (_,y1)
ltInterval (Itv (NegInfinity,x2)) (Itv (y1,Finite y2)) = 
  (intersectionInterval (Itv (NegInfinity, x2)) (Itv (NegInfinity, Finite (y2-1))),
   intersectionInterval (Itv (NegInfinity, PosInfinity)) (Itv (y1, Finite y2)))
-- case (-inf,_) < (_,+inf)
ltInterval (Itv (NegInfinity,x2)) (Itv (y1,PosInfinity)) = 
  (intersectionInterval (Itv (NegInfinity, x2)) (Itv (NegInfinity, PosInfinity)),
   intersectionInterval (Itv (NegInfinity, PosInfinity)) (Itv (y1, PosInfinity)))
-- case when one of the intervals is not correctly formatted
ltInterval x y = ltInterval (normalizeInterval x) (normalizeInterval y)

-- Normalize the intervals before performing the less or equal than operation.
leqInterval :: Interval -> Interval -> (Interval, Interval)
leqInterval itv1 itv2 = leqInterval' itv1' itv2'
  where 
    itv1' = normalizeInterval itv1
    itv2' = normalizeInterval itv2

-- Peform the actual less or equal than operation:
-- Less than operation [<=] ([a,b],[c,d]) = ([a,b] /\ [-inf, d], [a,+inf] /\ [c,d]).
leqInterval' :: Interval -> Interval -> (Interval, Interval)
leqInterval' EmptyItv _ = (EmptyItv, EmptyItv)
leqInterval' _ EmptyItv = (EmptyItv, EmptyItv)
leqInterval' (Itv (x1,x2)) (Itv (y1,y2)) = 
   (intersectionInterval (Itv (x1,x2)) (Itv (NegInfinity, y2)),
   intersectionInterval (Itv (x1,PosInfinity)) (Itv (y1,y2)))


------------------- Widening & Narrowing ------------------------

-- Performs widening operation in two intervals.
wideningInterval :: Interval -> Interval -> Interval
wideningInterval x EmptyItv = x
wideningInterval EmptyItv x = x
wideningInterval (Itv (x1,x2)) (Itv (y1, y2)) =
  Itv (x3,y3) 
  where
  x3 = if y1 < x1 then NegInfinity else x1
  y3 = if y2 > x2 then PosInfinity else x2

-- Performs narrowing operation in two intervals.
narrowingInterval :: Interval -> Interval -> Interval
narrowingInterval _ EmptyItv = EmptyItv
narrowingInterval EmptyItv _ = EmptyItv
narrowingInterval (Itv (x1,x2)) (Itv (y1, y2)) =
  Itv (x3,y3) 
  where
  x3 = if x1 == NegInfinity then y1 else x1
  y3 = if x2 == PosInfinity then y2 else x2

------------------- Interval Analysis state ------------------------

-- State that associates a register with an interval.
type ItvState = [(Reg, Interval)]

-- Initialize state with every register associated with an empty interval.
initialStateItv :: ItvState
initialStateItv = [
    (Reg 0, EmptyItv), (Reg 1, EmptyItv), (Reg 2, EmptyItv), 
    (Reg 3, EmptyItv), (Reg 4, EmptyItv), (Reg 5, EmptyItv), 
    (Reg 6, EmptyItv), (Reg 7, EmptyItv), (Reg 8, EmptyItv), 
    (Reg 9, EmptyItv), (Reg 10, EmptyItv)]

------------------- Interval Analysis ------------------------

-- Perform the interval analysis on a set of equations.
intervalAnalysis :: Equations -> [ItvState]
intervalAnalysis eq = fixpointItvAnalysis eqList state
    where
        eqList = Map.toList eq 
        state = replicate (length eqList) initialStateItv

-- Perform fixpoint computation for the analysis.
fixpointItvAnalysis :: [(Label, [(Label, Stmt)])] -> [ItvState] -> [ItvState]
fixpointItvAnalysis eq state =
    if state == newState then newState else fixpointItvAnalysis eq newState
        where 
            newState = foldl updateItvState state eq

-- This function updates the state of a program point after it is analyzed.
updateItvState :: [ItvState] -> (Label, [(Label, Stmt)]) -> [ItvState]
updateItvState state (nodeIdx, eqs) = 
  before ++ [state'] ++ after
  where
    state' = processItvElement Nothing state (nodeIdx, eqs)
    before = take nodeIdx state 
    after = drop (nodeIdx + 1) state

-- Process the equations for a specific node, returning the updated state.     
processItvElement :: Maybe ItvState -> [ItvState] -> (Label, [(Label, Stmt)]) -> ItvState
processItvElement (Nothing) states (nodeIdx,[]) = states !! nodeIdx
processItvElement (Just state) _ (_,[]) = state
processItvElement unionState states (currentNode, ((prevNode, stmt):es)) = 
    case unionState of
      Nothing -> processItvElement (Just state) states (currentNode, es)
      Just uState -> processItvElement(Just (unionStt uState state)) states (currentNode, es)
  where 
    prevState = (states !! prevNode)
    state = updateItvUsingStmt prevState stmt 

-- Update a node's state by analysing the the equation and then updating the interval(s) associated with 
-- the register(s) used in the equation. It also updates the memory value for memory handling operations.
updateItvUsingStmt :: ItvState -> Stmt -> ItvState

-- Process Binary operations
updateItvUsingStmt state (AssignReg r (Bin e)) =     
  case lookup r state of 
      Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
      _ -> state'
  where
    newItv = processBinaryExpression state e
    state' = updateRegisterValue r newItv state

-- Process Mov operation
updateItvUsingStmt state (AssignReg r (Mv ri)) =
    case lookup r state of 
        Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
        _ -> state'
    where 
        newValue = getRegisterImmediateToInterval state ri
        state' = updateRegisterValue r newValue state

-- Process Unary operations
updateItvUsingStmt state (AssignReg r (Un e)) = 
  case lookup r state of 
      Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
      _ -> state'
  where
    newItv = processUnaryExpression state e
    state' = updateRegisterValue r newItv state

-- TODO Process Store operations
updateItvUsingStmt state (StoreInMem r offset ri) = undefined

-- TODO Process Load operation with register as index
updateItvUsingStmt state (LoadFromMemReg r r' offset) = undefined

-- TODO Process Load operation with Imm as index
updateItvUsingStmt state (LoadFromMemImm r i) = undefined

-- Process conditional jumps
updateItvUsingStmt state (If cond _) = processCondition state cond

-- Process Unconditional jump
updateItvUsingStmt state (CallOp _) = state

-- Process Call operation
updateItvUsingStmt state (Goto _) = state


------------- Functions related to states handling ------------------------

-- TODO Process binary operations, by utilizing the arithmetic operations above.
processBinaryExpression :: ItvState -> BinaryExp -> Interval
processBinaryExpression state e = undefined

-- Process unary expressions, for Little Endian and Big Endian, I assume that
-- the value does not change. In the case of Neg r, the interval associated is
-- negated, for example [a, b] becomes [-b, -a].
processUnaryExpression :: ItvState -> UnaryExp -> Interval
processUnaryExpression state e =
    case e of 
    LeOp r -> getRegisterInterval state r -- Identity
    BeOp r -> getRegisterInterval state r -- Identity
    NegOp r -> case itv of -- Negate the interval
                  Itv (NegInfinity, Finite n) -> Itv (Finite (-n), PosInfinity)
                  Itv (Finite n, PosInfinity) -> Itv (NegInfinity, Finite (-n))
                  Itv (Finite n1, Finite n2) -> Itv (Finite (-n2), Finite (-n1))
                  _ -> itv
      where
        itv = normalizeInterval $ getRegisterInterval state r

-- Process a condition by utilizing the logical operations, updating the state for each
-- operand.
processCondition :: ItvState -> Condition -> ItvState
processCondition state e = 
  case e of 
    --Identity
    NotEqual _ _ -> state
    -- Equal operation 
    Equal r ri -> state'
      where 
        constraint = getRegisterImmediateToInterval state ri
        regValue = getRegisterInterval state r
        (newValr, newValri) = eqInterval regValue constraint
        updatedState = updateRegisterValue r newValr state
        state' = updateRegisterImmValue ri newValri updatedState
    -- Less than operation
    LessThan r ri -> state'
      where 
        constraint = getRegisterImmediateToInterval state ri
        regValue = getRegisterInterval state r
        (newValr, newValri) = ltInterval regValue constraint
        updatedState = updateRegisterValue r newValr state
        state' = updateRegisterImmValue ri newValri updatedState
    -- Less or equal than operation
    LessEqual r ri -> state'
      where 
        constraint = getRegisterImmediateToInterval state ri
        regValue = getRegisterInterval state r
        (newValr, newValri) = leqInterval regValue constraint
        updatedState = updateRegisterValue r newValr state
        state' = updateRegisterImmValue ri newValri updatedState
    -- Greater than is equivalent to less than with the operands inverted
    GreaterThan r ri -> state'
      where 
        constraint = getRegisterImmediateToInterval state ri
        regValue = getRegisterInterval state r
        (newValri, newValr) = ltInterval constraint regValue
        updatedState = updateRegisterValue r newValr state
        state' = updateRegisterImmValue ri newValri updatedState
    -- Greater or equal than is equivalent to less or equal than with the operands inverted
    GreaterEqual r ri -> state'
      where 
        constraint = getRegisterImmediateToInterval state ri
        regValue = getRegisterInterval state r
        (newValri, newValr) = leqInterval constraint regValue
        updatedState = updateRegisterValue r newValr state
        state' = updateRegisterImmValue ri newValri updatedState

-- If RegImm is a register it returns the interval associated to a register 
-- in the given state, if it is an (Imm n) it returns an interval [n,n].
getRegisterImmediateToInterval :: ItvState -> RegImm -> Interval
getRegisterImmediateToInterval state ri = case ri of 
      R r' -> getRegisterInterval state r'
      Imm n -> constantInterval (fromIntegral n)

-- Returns the interval associated to a register in the given state.
getRegisterInterval :: ItvState -> Reg -> Interval
getRegisterInterval state r =   
    case lookup r state of
        Just itv -> itv 
        Nothing -> error "Register not found in state"

-- If the RegImm is a register updates the interval in the state, 
-- otherwise it returns the state without changes.
updateRegisterImmValue :: RegImm -> Interval -> ItvState -> ItvState
updateRegisterImmValue ri itv state = 
    case ri of
        R r -> updateRegisterValue r itv state
        Imm _ -> state

-- Updates the value of a register in the state.
updateRegisterValue :: Reg -> Interval -> ItvState -> ItvState
updateRegisterValue r itv = map (\(reg, i) -> 
    if reg == r 
        then (reg, itv)
        else (reg, i))
  
-- Union of two states.
unionStt :: ItvState -> ItvState -> ItvState
unionStt = zipWith combine
  where
    combine (reg, itv1) (_, itv2) = (reg, unionInterval itv1 itv2)
