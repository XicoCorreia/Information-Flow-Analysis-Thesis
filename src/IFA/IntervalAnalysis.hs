module IFA.IntervalAnalysis where

import qualified Data.Map as Map

import IFA.Types
import Ebpf.Asm

------------------- Itv Analysis Types ------------------------
-- Represents the possible values in an interval.
data ItvVal = 
    Finite Int
  | NegInfinity
  | PosInfinity
    deriving (Show)

instance Eq ItvVal where
  (Finite x) == (Finite y)       = x == y
  NegInfinity == NegInfinity     = True
  PosInfinity == PosInfinity     = True
  _ == _                         = False

instance Ord ItvVal where
  compare (Finite x) (Finite y)       = compare x y
  compare (Finite _) NegInfinity      = GT
  compare (Finite _) PosInfinity      = LT
  compare NegInfinity (Finite _)      = LT
  compare NegInfinity NegInfinity     = EQ
  compare NegInfinity PosInfinity     = LT
  compare PosInfinity (Finite _)      = GT
  compare PosInfinity NegInfinity     = GT
  compare PosInfinity PosInfinity     = EQ

-- Itv, can be empty if not initialized.
data Itv = 
    Itv (ItvVal, ItvVal)
  | EmptyItv
    deriving (Show, Eq)

-- State that associates a register with an interval.
type ItvState = [(Reg, Itv)]

------------------- Itv Operations ------------------------

-- Perform the union of two intervals.
unionInterval :: Itv -> Itv -> Itv
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
intersectionInterval :: Itv -> Itv -> Itv
intersectionInterval EmptyItv _ = EmptyItv
intersectionInterval _ EmptyItv = EmptyItv
-- case (-inf, +inf) /\ ...
intersectionInterval (Itv (NegInfinity, PosInfinity)) x = x
-- ... /\ case (-inf, +inf)
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
normalizeInterval :: Itv -> Itv
normalizeInterval  (Itv (Finite x1, Finite x2)) = 
  if x1 <= x2 
    then (Itv (Finite x1, Finite x2)) 
    else EmptyItv
normalizeInterval  (Itv (_, NegInfinity)) = EmptyItv
normalizeInterval  (Itv (PosInfinity, _)) = EmptyItv
normalizeInterval x = x

-- Takes an int n and returns the constant as an interval [n,n].
constantInterval :: Int -> Itv
constantInterval x = (Itv (Finite x, Finite x)) 

------------------- Arithmetic Itv Operations ------------------------

-- Add operation [+] ([a,b], [c,d]) = [a+c,b+d] 
addInterval :: Itv -> Itv -> Itv
addInterval EmptyItv _ = EmptyItv
addInterval _ EmptyItv = EmptyItv
-- case (-inf, +inf) + ...
addInterval (Itv (NegInfinity, PosInfinity)) _ = (Itv (NegInfinity, PosInfinity))
-- case ... + (-inf, +inf)
addInterval _ (Itv (NegInfinity, PosInfinity)) = (Itv (NegInfinity, PosInfinity))
-- case (-inf,x) + ...
addInterval (Itv (NegInfinity, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (x2+y2))
addInterval (Itv (NegInfinity, Finite _)) (Itv (Finite _, PosInfinity)) = Itv (NegInfinity, PosInfinity)
addInterval (Itv (NegInfinity, Finite x2)) (Itv (Finite _, Finite y2)) = Itv (NegInfinity, Finite (x2+y2))
-- case (x,+inf) + ...
addInterval (Itv (Finite _, PosInfinity)) (Itv (NegInfinity, Finite _)) = Itv (NegInfinity, PosInfinity)
addInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (x1+y1), PosInfinity)
addInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, Finite _)) = Itv (Finite (x1+y1), PosInfinity)
-- case (x1,x2) + ...
addInterval  (Itv (Finite _, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (x2 + y2))
addInterval (Itv (Finite x1, Finite _)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (x1+y1), PosInfinity)
addInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (x1 + y1), Finite (x2 + y2))
-- case when one of the intervals is not correctly formatted
addInterval x y = addInterval (normalizeInterval x) (normalizeInterval y)

-- Sub operation [-] ([a,b], [c,d]) = [a-d,b-c] 
subInterval :: Itv -> Itv -> Itv
subInterval EmptyItv _ = EmptyItv
subInterval _ EmptyItv = EmptyItv
-- case (-inf, +inf) - ...
subInterval (Itv (NegInfinity, PosInfinity)) _ = (Itv (NegInfinity, PosInfinity))
-- case .. - (-inf, +inf)
subInterval _ (Itv (NegInfinity, PosInfinity)) = (Itv (NegInfinity, PosInfinity))
-- case (-inf,x) + ...
subInterval (Itv (NegInfinity, Finite _)) (Itv (NegInfinity, Finite _)) = Itv (NegInfinity, PosInfinity)
subInterval (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (NegInfinity, Finite (x2-y1))
subInterval (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, Finite _)) = Itv (NegInfinity, Finite (x2+y1))
-- case (x,+inf) + ...
subInterval (Itv (Finite x1, PosInfinity)) (Itv (NegInfinity, Finite y2)) = Itv (Finite (x1-y2), PosInfinity)
subInterval (Itv (Finite _, PosInfinity)) (Itv (Finite _, PosInfinity)) = Itv (NegInfinity, PosInfinity)
subInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite _, Finite y2)) = Itv (Finite (x1+y2), PosInfinity)
-- case (x1,x2) + ...
subInterval  (Itv (Finite x1, Finite _)) (Itv (NegInfinity, Finite y2)) = Itv (Finite (x1 - y2), PosInfinity)
subInterval (Itv (Finite _, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (NegInfinity, Finite (x2 - y1))
subInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (x1 - y2), Finite (x2 - y1))
-- case when one of the intervals is not correctly formatted
subInterval x y = subInterval (normalizeInterval x) (normalizeInterval y)

-- Mul operation [-] ([a,b], [c,d]) = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)]
mulInterval :: Itv -> Itv -> Itv
mulInterval x y = mulInterval' (normalizeInterval x) (normalizeInterval y)
  where
    mulInterval' :: Itv -> Itv -> Itv
    mulInterval' EmptyItv _ = EmptyItv
    mulInterval' _ EmptyItv = EmptyItv
    mulInterval' (Itv (a,b)) (Itv (c,d)) = Itv(minimum [ac,ad,bc,bd], maximum [ac,ad,bc,bd])
      where 
        ac = mul' a c
        ad = mul' a d
        bc = mul' b c
        bd = mul' b d

-- Auxiliar operation for multiplication that computes the multiplication value
mul' :: ItvVal -> ItvVal -> ItvVal 
-- -inf * ...
mul' NegInfinity PosInfinity = NegInfinity
mul' NegInfinity (Finite x) = 
  if x == 0 
    then Finite 0
    else if x < 0
      then PosInfinity
      else NegInfinity
mul' NegInfinity NegInfinity = PosInfinity
-- +inf * ...
mul' PosInfinity NegInfinity = NegInfinity 
mul' PosInfinity (Finite x) =
    if x == 0 
    then Finite 0
    else if x < 0
      then NegInfinity
      else PosInfinity
-- finite * ...
mul' (Finite x) PosInfinity = mul' PosInfinity (Finite x)
mul' (Finite x) (Finite y) = Finite (x*y) 
mul' (Finite x) NegInfinity = mul' NegInfinity (Finite x) 
mul' x y = error $ "It shouldnt reach here:" ++ (show x) ++ (show y)

-- TODO Div operation 
divInterval :: Itv -> Itv -> Itv
divInterval _ _ = undefined

-- TODO Or operation 
orInterval :: Itv -> Itv -> Itv
orInterval _ _ = undefined

-- TODO And operation 
andInterval :: Itv -> Itv -> Itv
andInterval _ _ = undefined

-- TODO Lsh operation
lshInterval :: Itv -> Itv -> Itv
lshInterval _ _ = undefined

-- TODO Rsh operation
rshInterval :: Itv -> Itv -> Itv
rshInterval _ _ = undefined

-- TODO Mod operation 
modInterval :: Itv -> Itv -> Itv
modInterval _ _ = undefined

-- TODO Xor operation 
xorInterval :: Itv -> Itv -> Itv
xorInterval _ _ = undefined

-- TODO Arsh operation
arshInterval :: Itv -> Itv -> Itv
arshInterval _ _ = undefined


------------------- Logical Itv Operations ------------------------

-- Equal operation [=] ([a,b],[c,d]) = ([a,b] /\ [c,d], [a,b] /\ [c,d]).
eqInterval :: Itv -> Itv -> (Itv, Itv)
eqInterval x y = (intersectionInterval x y, intersectionInterval x y)

-- Less than operation [<] ([a,b],[c,d]) = ([a,b] /\ [-inf, d-1], [a+1,+inf] /\ [c,d]).
ltInterval :: Itv -> Itv -> (Itv, Itv)
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
leqInterval :: Itv -> Itv -> (Itv, Itv)
leqInterval itv1 itv2 = leqInterval' itv1' itv2'
  where 
    itv1' = normalizeInterval itv1
    itv2' = normalizeInterval itv2

-- Peform the actual less or equal than operation:
-- Less than operation [<=] ([a,b],[c,d]) = ([a,b] /\ [-inf, d], [a,+inf] /\ [c,d]).
leqInterval' :: Itv -> Itv -> (Itv, Itv)
leqInterval' EmptyItv _ = (EmptyItv, EmptyItv)
leqInterval' _ EmptyItv = (EmptyItv, EmptyItv)
leqInterval' (Itv (x1,x2)) (Itv (y1,y2)) = 
   (intersectionInterval (Itv (x1,x2)) (Itv (NegInfinity, y2)),
   intersectionInterval (Itv (x1,PosInfinity)) (Itv (y1,y2)))


------------------- Widening & Narrowing ------------------------

-- Performs widening operation in two intervals.
wideningInterval :: Itv -> Itv -> Itv
wideningInterval x EmptyItv = x
wideningInterval EmptyItv x = x
wideningInterval (Itv (x1,x2)) (Itv (y1, y2)) =
  Itv (x3,y3) 
  where
  x3 = if y1 < x1 then NegInfinity else x1
  y3 = if y2 > x2 then PosInfinity else x2

-- Performs narrowing operation in two intervals.
narrowingInterval :: Itv -> Itv -> Itv
narrowingInterval _ EmptyItv = EmptyItv
narrowingInterval EmptyItv _ = EmptyItv
narrowingInterval (Itv (x1,x2)) (Itv (y1, y2)) =
  Itv (x3,y3) 
  where
  x3 = if x1 == NegInfinity then y1 else x1
  y3 = if x2 == PosInfinity then y2 else x2

------------------- Itv Analysis ------------------------

-- Perform the interval analysis on a set of equations.
intervalAnalysis :: Equations -> ItvState -> [ItvState]
intervalAnalysis eq initialStateItv = fixpointItvAnalysis eqList state
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
        newValue = getRegisterImmediateInterval state ri
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

-- Process binary operations, by utilizing the arithmetic operations above.
processBinaryExpression :: ItvState -> BinaryExp -> Itv
processBinaryExpression state e = 
    case e of
      AddOp r ri -> processBinaryExpression' addInterval r ri state
      SubOp r ri -> processBinaryExpression' mulInterval r ri state
      MulOp r ri -> processBinaryExpression' mulInterval r ri state
      DivOp r ri -> processBinaryExpression' divInterval r ri state
      OrOp  r ri -> processBinaryExpression' orInterval r ri state
      AndOp r ri -> processBinaryExpression' andInterval r ri state
      LshOp r ri -> processBinaryExpression' lshInterval r ri state
      RshOp r ri -> processBinaryExpression' rshInterval r ri state
      ModOp r ri -> processBinaryExpression' modInterval r ri state
      XorOp r ri -> processBinaryExpression' xorInterval r ri state
      ArshOp r ri -> processBinaryExpression' arshInterval r ri state

-- Auxiliary function for binary expressions processing that computes the desire arithmetic 
-- operation with the two operands.
processBinaryExpression' :: (Itv -> Itv -> Itv) -> Reg -> RegImm -> ItvState -> Itv
processBinaryExpression' fun r ri state = fun op1 op2
  where
    op1 = getRegisterInterval state r
    op2 = getRegisterImmediateInterval state ri

-- Process unary expressions, for Little Endian and Big Endian, I assume that
-- the value does not change. In the case of Neg r, the interval associated is
-- negated, for example [a, b] becomes [-b, -a].
processUnaryExpression :: ItvState -> UnaryExp -> Itv
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
    Equal r ri ->  processCondition' ltInterval (R r) ri state
    -- Less than operation
    LessThan r ri ->  processCondition' ltInterval (R r) ri state
    -- Less or equal than operation
    LessEqual r ri -> processCondition' ltInterval (R r) ri state
    -- Greater than is equivalent to less than with the operands inverted
    GreaterThan r ri -> processCondition' ltInterval ri (R r) state
    -- Greater or equal than is equivalent to less or equal than with the operands inverted
    GreaterEqual r ri -> processCondition' leqInterval ri (R r) state

-- Auxiliary function for condition processing that computes the desire logical
-- operation with the two operands.
processCondition' :: (Itv -> Itv -> (Itv, Itv)) -> RegImm -> RegImm -> ItvState -> ItvState
processCondition' fun ri1 ri2 state = state'
  where
        op1 = getRegisterImmediateInterval state ri1
        op2 = getRegisterImmediateInterval state ri2
        (newVal1, newVal2) = fun op1 op2
        updatedState = updateRegisterImmValue ri1 newVal1 state
        state' = updateRegisterImmValue ri2 newVal2 updatedState

-- If RegImm is a register it returns the interval associated to a register 
-- in the given state, if it is an (Imm n) it returns an interval [n,n].
getRegisterImmediateInterval :: ItvState -> RegImm -> Itv
getRegisterImmediateInterval state ri = case ri of 
      R r' -> getRegisterInterval state r'
      Imm n -> constantInterval (fromIntegral n)

-- Returns the interval associated to a register in the given state.
getRegisterInterval :: ItvState -> Reg -> Itv
getRegisterInterval state r =   
    case lookup r state of
        Just itv -> itv 
        Nothing -> error "Register not found in state"

-- If the RegImm is a register updates the interval in the state, 
-- otherwise it returns the state without changes.
updateRegisterImmValue :: RegImm -> Itv -> ItvState -> ItvState
updateRegisterImmValue ri itv state = 
    case ri of
        R r -> updateRegisterValue r itv state
        Imm _ -> state

-- Updates the value of a register in the state.
updateRegisterValue :: Reg -> Itv -> ItvState -> ItvState
updateRegisterValue r itv = map (\(reg, i) -> 
    if reg == r 
        then (reg, itv)
        else (reg, i))
  
-- Union of two states.
unionStt :: ItvState -> ItvState -> ItvState
unionStt = zipWith combine
  where
    combine (reg, itv1) (_, itv2) = (reg, unionInterval itv1 itv2)
