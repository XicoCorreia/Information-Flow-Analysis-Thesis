module IFA.IntervalAnalysis (intervalAnalysis) where

import qualified Data.Map as Map

import IFA.Types
import Ebpf.Asm

------------------- Interval Analysis Types ------------------------

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

data Interval = 
    Itv (IntVal, IntVal)
  | EmptyItv
    deriving (Show, Eq)

------------------- Interval Operations ------------------------

unionInterval :: Interval -> Interval -> Interval
unionInterval (Itv (NegInfinity, PosInfinity)) _ = Itv (NegInfinity, PosInfinity)  
unionInterval _ (Itv (NegInfinity, PosInfinity)) = Itv (NegInfinity, PosInfinity)
unionInterval EmptyItv x = x
unionInterval x EmptyItv = x
unionInterval (Itv (NegInfinity, Finite x)) (Itv (NegInfinity, Finite y)) = Itv (NegInfinity, Finite (max x y))
unionInterval (Itv (NegInfinity, _)) (Itv (_, PosInfinity)) = Itv (NegInfinity, PosInfinity)
unionInterval (Itv (NegInfinity, Finite x2)) (Itv (_, Finite y2)) = Itv (NegInfinity, Finite (max x2 y2))
unionInterval (Itv (_, PosInfinity)) (Itv (NegInfinity, _)) = Itv (NegInfinity, PosInfinity)
unionInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (min x1 y1), PosInfinity)
unionInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, _)) = Itv (Finite (min x1 y1), PosInfinity)
unionInterval (Itv (_, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (max x2 y2))
unionInterval (Itv (Finite x1, _)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (min x1 y1), PosInfinity)
unionInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (min x1 y1), Finite (max x2 y2))
-- case when 1 of the intervals is not correctly formatted
unionInterval x y = unionInterval (normalizeInterval x) (normalizeInterval y)

intersectionInterval :: Interval -> Interval -> Interval
intersectionInterval (Itv (NegInfinity, PosInfinity)) x = x
intersectionInterval x (Itv (NegInfinity, PosInfinity)) = x
intersectionInterval EmptyItv _ = EmptyItv
intersectionInterval _ EmptyItv = EmptyItv
intersectionInterval (Itv (NegInfinity, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (min x2 y2))
intersectionInterval (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (Finite y1, Finite x2)
intersectionInterval (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite y1, Finite (min x2 y2))
intersectionInterval (Itv (Finite x1, PosInfinity)) (Itv (NegInfinity, Finite y2)) = Itv (Finite x1, Finite y2)
intersectionInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (max x1 y1), PosInfinity)
intersectionInterval (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, Finite y2)) = Itv (Finite (max x1 y1), Finite y2)
intersectionInterval (Itv (Finite x1, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (Finite x1, Finite (min x2 y2))
intersectionInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (max x1 y1), Finite x2)
intersectionInterval (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (max x1 y1), Finite (min x2 y2))
-- case when 1 of the intervals is not correctly formatted
intersectionInterval x y = intersectionInterval (normalizeInterval x) (normalizeInterval y)


normalizeInterval :: Interval -> Interval
normalizeInterval  (Itv (Finite x1, Finite x2)) = 
  if x1 <= x2 
    then (Itv (Finite x1, Finite x2)) 
    else EmptyItv
normalizeInterval  (Itv (_, NegInfinity)) = EmptyItv
normalizeInterval  (Itv (PosInfinity, _)) = EmptyItv
normalizeInterval x = x

constantInterval :: Int -> Interval
constantInterval x = (Itv (Finite x, Finite x)) 

------------------- Arithmetic Interval Operations ------------------------

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
-- case when 1 of the intervals is not correctly formatted
addInterval x y = addInterval (normalizeInterval x) (normalizeInterval y)

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
-- case when 1 of the intervals is not correctly formatted
subInterval x y = subInterval (normalizeInterval x) (normalizeInterval y)

-- TODO Mul not implemented
mulInterval :: Interval -> Interval -> Interval
mulInterval _ _ = undefined

-- TODO Div not implemented
divInterval :: Interval -> Interval -> Interval
divInterval _ _ = undefined

------------------- Logical Interval Operations ------------------------

eqInterval :: Interval -> Interval -> (Interval, Interval)
eqInterval x y = (intersectionInterval x y, intersectionInterval x y)

-- TODO NOTEQUAL not implemented
noteqInterval :: Interval -> Interval -> (Interval, Interval)
noteqInterval _ _ = undefined

ltInterval :: Interval -> Interval -> (Interval, Interval)
ltInterval EmptyItv _ = (EmptyItv, EmptyItv)
ltInterval _ EmptyItv = (EmptyItv, EmptyItv)
ltInterval (Itv (Finite x1,x2)) (Itv (y1,Finite y2)) = 
  (intersectionInterval (Itv (Finite x1,x2)) (Itv (NegInfinity, Finite (y2-1))),
   intersectionInterval (Itv (Finite (x1 + 1),x2)) (Itv (y1,Finite y2)))
ltInterval (Itv (NegInfinity,x2)) (Itv (y1,Finite y2)) = 
  (intersectionInterval (Itv (NegInfinity,x2)) (Itv (NegInfinity, Finite (y2-1))),
   intersectionInterval (Itv (NegInfinity,x2)) (Itv (y1,Finite y2)))
ltInterval (Itv (Finite x1,x2)) (Itv (y1,PosInfinity)) = 
  (intersectionInterval (Itv (Finite x1,x2)) (Itv (NegInfinity, PosInfinity)),
   intersectionInterval (Itv (Finite (x1 + 1),x2)) (Itv (y1, PosInfinity)))
ltInterval (Itv (NegInfinity,x2)) (Itv (y1,PosInfinity)) = 
  (intersectionInterval (Itv (NegInfinity,x2)) (Itv (NegInfinity, PosInfinity)),
   intersectionInterval (Itv (NegInfinity,x2)) (Itv (y1, PosInfinity)))
-- case when 1 of the intervals is not correctly formatted
ltInterval x y = ltInterval (normalizeInterval x) (normalizeInterval y)

leqInterval :: Interval -> Interval -> (Interval, Interval)
leqInterval EmptyItv _ = (EmptyItv, EmptyItv)
leqInterval _ EmptyItv = (EmptyItv, EmptyItv)
leqInterval (Itv (x1,x2)) (Itv (y1,y2)) = 
   (intersectionInterval (Itv (x1,x2)) (Itv (NegInfinity, y2)),
   intersectionInterval (Itv (x1,PosInfinity)) (Itv (y1,y2)))
-- There is no bad format case this time, can be an issue

------------------- Widening & Narrowing ------------------------

wideningInterval :: Interval -> Interval -> Interval
wideningInterval x EmptyItv = x
wideningInterval EmptyItv x = x
wideningInterval (Itv (x1,x2)) (Itv (y1, y2)) =
  Itv (x3,y3) 
  where
  x3 = if y1 < x1 then NegInfinity else x1
  y3 = if y2 > x2 then PosInfinity else x2

narrowingInterval :: Interval -> Interval -> Interval
narrowingInterval _ EmptyItv = EmptyItv
narrowingInterval EmptyItv _ = EmptyItv
narrowingInterval (Itv (x1,x2)) (Itv (y1, y2)) =
  Itv (x3,y3) 
  where
  x3 = if x1 == NegInfinity then y1 else x1
  y3 = if x2 == PosInfinity then y2 else x2

------------------- Interval Analysis ops ------------------------

type ItvState = [(Reg, Interval)]

initialStateItv :: ItvState
initialStateItv = [
    (Reg 0, EmptyItv), (Reg 1, EmptyItv), (Reg 2, EmptyItv), 
    (Reg 3, EmptyItv), (Reg 4, EmptyItv), (Reg 5, EmptyItv), 
    (Reg 6, EmptyItv), (Reg 7, EmptyItv), (Reg 8, EmptyItv), 
    (Reg 9, EmptyItv), (Reg 10, EmptyItv)]

-- ItvState operations 
unionStt :: ItvState -> ItvState -> ItvState
unionStt [] s2 = s2 -- When one is empty the other one is returned 
unionStt s1 [] = s1
unionStt s1 s2 =
  let
    -- Go through each element in s1 and check if it's in s2
    mergeItvState [] acc = acc  -- Base case: when s1 is empty, return accumulated result
    mergeItvState ((v1, int1):xs) acc =
      case lookup v1 s2 of
        Just int2 -> mergeItvState xs ((v1, unionInterval int1 int2) : acc)  -- If v1 is found in s2, union the intervals
        Nothing   -> mergeItvState xs ((v1, int1) : acc)                -- If v1 is not found in s2, just add it from s1
    -- Once done with s1, we still need to include any (VName, Interval) from s2 that wasn't in s1
    remainingS2 = filter (\(v2, _) -> v2 `notElem` map fst s1) s2
  in
    mergeItvState s1 [] ++ remainingS2

-- TODO ? 
combineNewPrev :: ItvState -> ItvState -> ItvState
combineNewPrev [] s2 = s2 -- When one is empty the other one is returned 
combineNewPrev s1 [] = s1
combineNewPrev s1 s2 = s1 ++ (filter (\(v2, _) -> v2 `notElem` map fst s1) s2)







------------------- Interval Analysis ------------------------

intervalAnalysis :: Equations -> [ItvState]
intervalAnalysis eq = fixpointItvAnalysis eqList state
    where
        eqList = Map.toList eq 
        state = replicate (length eqList) initialStateItv

fixpointItvAnalysis :: [(Label, [(Label, Stmt)])] -> [ItvState] -> [ItvState]
fixpointItvAnalysis eq state =
    if state == newState then newState else fixpointItvAnalysis eq newState
        where 
            newState = foldl updateItvState state eq


updateItvState :: [ItvState] -> (Label, [(Label, Stmt)]) -> [ItvState]
updateItvState state (nodeIdx, eqs) = 
  before ++ [state'] ++ after
  where
    state' = processItvElement Nothing state (nodeIdx, eqs)
    before = take nodeIdx state 
    after = drop (nodeIdx + 1) state


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
-- TODO 
updateItvUsingStmt :: ItvState -> Stmt -> ItvState
updateItvUsingStmt state (AssignReg r (Mv ri)) =
    case lookup r state of 
        Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
        _ -> state'
    where 
        newValue = registerImmediateToInterval state ri
        state' = updateRegisterValue r newValue state
updateItvUsingStmt s _ = s


------------- Functions related to states handling ------------------------

registerImmediateToInterval :: ItvState -> RegImm -> Interval
registerImmediateToInterval state ri = case ri of 
      R r' -> getRegisterInterval state r'
      Imm n -> Itv (Finite (fromIntegral n), Finite (fromIntegral n))

getRegisterInterval :: ItvState -> Reg -> Interval
getRegisterInterval s r =   
    case lookup r s of
        Just itv -> itv 
        Nothing -> error "Register not found in state"

updateRegisterValue :: Reg -> Interval -> ItvState -> ItvState
updateRegisterValue r itv = map (\(reg, i) -> 
    if reg == r 
        then (reg, itv)
        else (reg, i))