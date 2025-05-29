module IFA.IntervalAnalysis (intervalAnalysis) where

import qualified Data.Map as Map
import Data.Maybe (mapMaybe)
import Data.Bits

import IFA.Types
import Ebpf.Asm

------------------- Itv Operations ------------------------

-- Perform the union of two intervals.
unionInterval :: Itv -> Itv -> Itv
unionInterval a b = normalizeInterval $ unionInterval' (normalizeInterval a) (normalizeInterval b)
  where 
    unionInterval' :: Itv -> Itv -> Itv
    unionInterval' EmptyItv x = x
    unionInterval' x EmptyItv = x
    -- case (-inf, +inf) \/ ...
    unionInterval' (Itv (NegInfinity, PosInfinity)) _ = Itv (NegInfinity, PosInfinity)  
    -- case (-inf,x) \/ ...
    unionInterval' (Itv (NegInfinity, Finite _)) (Itv (_, PosInfinity)) = Itv (NegInfinity, PosInfinity)
    unionInterval' (Itv (NegInfinity, Finite x)) (Itv (_, Finite y)) = Itv (NegInfinity, Finite (max x y))
    -- case (x,+inf) \/ ...
    unionInterval' (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, _)) = Itv (Finite (min x1 y1), PosInfinity)
    unionInterval' (Itv (Finite _, PosInfinity)) (Itv (NegInfinity, _)) = Itv (NegInfinity, PosInfinity)
    -- case (x1, x2) \/ ...
    unionInterval' (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (min x1 y1), Finite (max x2 y2))
    unionInterval' (Itv (Finite _, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (max x2 y2))
    unionInterval' (Itv (Finite x1, Finite _)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (min x1 y1), PosInfinity)
    unionInterval' (Itv (Finite _, Finite _)) (Itv (NegInfinity, PosInfinity)) = Itv (NegInfinity, PosInfinity)  
    unionInterval' x y = error $ "It shouldnt reach here: " ++ (show x) ++ " " ++ (show y) -- Just to avoid non-exhaustive pattern

-- Perform the intersection of two intervals.
intersectionInterval :: Itv -> Itv -> Itv
intersectionInterval a b = normalizeInterval $ intersectionInterval' (normalizeInterval a) (normalizeInterval b)
  where
    intersectionInterval' EmptyItv _ = EmptyItv
    intersectionInterval' _ EmptyItv = EmptyItv
    -- case (-inf, +inf) /\ ...
    intersectionInterval' (Itv (NegInfinity, PosInfinity)) x = x
    -- ... /\ case (-inf, +inf)
    intersectionInterval' x (Itv (NegInfinity, PosInfinity)) = x
    -- case (-inf,x) /\ ...
    intersectionInterval' (Itv (NegInfinity, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (min x2 y2))
    intersectionInterval' (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (Finite y1, Finite x2)
    intersectionInterval' (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite y1, Finite (min x2 y2))
    -- case (x,+inf) /\ ...
    intersectionInterval' (Itv (Finite x1, PosInfinity)) (Itv (NegInfinity, Finite y2)) = Itv (Finite x1, Finite y2)
    intersectionInterval' (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (max x1 y1), PosInfinity)
    intersectionInterval' (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, Finite y2)) = Itv (Finite (max x1 y1), Finite y2)
    -- case (x1,x2) /\ ...
    intersectionInterval' (Itv (Finite x1, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (Finite x1, Finite (min x2 y2))
    intersectionInterval' (Itv (Finite x1, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (max x1 y1), Finite x2)
    intersectionInterval' (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (max x1 y1), Finite (min x2 y2))
    intersectionInterval' x y = error $ "It shouldnt reach here: " ++ (show x) ++ " " ++ (show y) -- Just to avoid non-exhaustive pattern

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

-- Add operation [+] ([a,b], [c,d]) = [a+c,b+d].
addInterval :: Itv -> Itv -> Itv
addInterval a b = addInterval' (normalizeInterval a) (normalizeInterval b)
  where
    addInterval' EmptyItv _ = EmptyItv
    addInterval' _ EmptyItv = EmptyItv
    -- case (-inf, +inf) + ...
    addInterval' (Itv (NegInfinity, PosInfinity)) _ = (Itv (NegInfinity, PosInfinity))
    -- case ... + (-inf, +inf)
    addInterval' _ (Itv (NegInfinity, PosInfinity)) = (Itv (NegInfinity, PosInfinity))
    -- case (-inf,x) + ...
    addInterval' (Itv (NegInfinity, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (x2+y2))
    addInterval' (Itv (NegInfinity, Finite _)) (Itv (Finite _, PosInfinity)) = Itv (NegInfinity, PosInfinity)
    addInterval' (Itv (NegInfinity, Finite x2)) (Itv (Finite _, Finite y2)) = Itv (NegInfinity, Finite (x2+y2))
    -- case (x,+inf) + ...
    addInterval' (Itv (Finite _, PosInfinity)) (Itv (NegInfinity, Finite _)) = Itv (NegInfinity, PosInfinity)
    addInterval' (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (x1+y1), PosInfinity)
    addInterval' (Itv (Finite x1, PosInfinity)) (Itv (Finite y1, Finite _)) = Itv (Finite (x1+y1), PosInfinity)
    -- case (x1,x2) + ...
    addInterval'  (Itv (Finite _, Finite x2)) (Itv (NegInfinity, Finite y2)) = Itv (NegInfinity, Finite (x2 + y2))
    addInterval' (Itv (Finite x1, Finite _)) (Itv (Finite y1, PosInfinity)) = Itv (Finite (x1+y1), PosInfinity)
    addInterval' (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (x1 + y1), Finite (x2 + y2))
    addInterval' x y = error $ "It shouldnt reach here: " ++ (show x) ++ " " ++ (show y) -- Just to avoid non-exhaustive pattern

-- Sub operation [-] ([a,b], [c,d]) = [a-d,b-c] .
subInterval :: Itv -> Itv -> Itv
subInterval a b = subInterval' (normalizeInterval a) (normalizeInterval b)
  where
    subInterval' EmptyItv _ = EmptyItv
    subInterval' _ EmptyItv = EmptyItv
    -- case (-inf, +inf) - ...
    subInterval' (Itv (NegInfinity, PosInfinity)) _ = (Itv (NegInfinity, PosInfinity))
    -- case .. - (-inf, +inf)
    subInterval' _ (Itv (NegInfinity, PosInfinity)) = (Itv (NegInfinity, PosInfinity))
    -- case (-inf,x) + ...
    subInterval' (Itv (NegInfinity, Finite _)) (Itv (NegInfinity, Finite _)) = Itv (NegInfinity, PosInfinity)
    subInterval' (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (NegInfinity, Finite (x2-y1))
    subInterval' (Itv (NegInfinity, Finite x2)) (Itv (Finite y1, Finite _)) = Itv (NegInfinity, Finite (x2+y1))
    -- case (x,+inf) + ...
    subInterval' (Itv (Finite x1, PosInfinity)) (Itv (NegInfinity, Finite y2)) = Itv (Finite (x1-y2), PosInfinity)
    subInterval' (Itv (Finite _, PosInfinity)) (Itv (Finite _, PosInfinity)) = Itv (NegInfinity, PosInfinity)
    subInterval' (Itv (Finite x1, PosInfinity)) (Itv (Finite _, Finite y2)) = Itv (Finite (x1+y2), PosInfinity)
    -- case (x1,x2) + ...
    subInterval' (Itv (Finite x1, Finite _)) (Itv (NegInfinity, Finite y2)) = Itv (Finite (x1 - y2), PosInfinity)
    subInterval' (Itv (Finite _, Finite x2)) (Itv (Finite y1, PosInfinity)) = Itv (NegInfinity, Finite (x2 - y1))
    subInterval' (Itv (Finite x1, Finite x2)) (Itv (Finite y1, Finite y2)) = Itv (Finite (x1 - y2), Finite (x2 - y1))
    subInterval' x y = error $ "It shouldnt reach here: " ++ (show x) ++ " " ++ (show y) -- Just to avoid non-exhaustive pattern

-- Mul operation [*] ([a,b], [c,d]) = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)].
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

-- Auxiliar operation for multiplication that computes the multiplication value.
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
mul' PosInfinity PosInfinity = PosInfinity
-- finite * ...
mul' (Finite x) PosInfinity = mul' PosInfinity (Finite x)
mul' (Finite x) (Finite y) = Finite (x*y) 
mul' (Finite x) NegInfinity = mul' NegInfinity (Finite x) 

-- Div operation [/] ([a,b], [c,d]) = [*] ([a,b], [1/d,1/c]).
divInterval :: Itv -> Itv -> Itv
divInterval x y = divInterval' (normalizeInterval x) (normalizeInterval y)
  where
    divInterval' :: Itv -> Itv -> Itv
    divInterval' EmptyItv _ = EmptyItv
    divInterval' _ EmptyItv = EmptyItv
    divInterval' (Itv (a,b)) (Itv (c,d)) = Itv(minimum [ac,ad,bc,bd], maximum [ac,ad,bc,bd])
      where 
        (c',d') = invert (c,d)
        ac = mul' a c'
        ad = mul' a d'
        bc = mul' b c'
        bd = mul' b d'

invert :: (ItvVal, ItvVal) -> (ItvVal, ItvVal)
invert (NegInfinity, PosInfinity) = ((Finite 0), (Finite 0))
invert (NegInfinity, (Finite 0)) = (NegInfinity, (Finite 0))
invert (NegInfinity, (Finite y)) = ((Finite (1 `div` y)), (Finite 0))
invert ((Finite 0), PosInfinity) = ((Finite 0), PosInfinity)
invert ((Finite x), PosInfinity) = ((Finite 0), (Finite (1 `div` x)))
invert ((Finite 0), (Finite 0)) = (NegInfinity, PosInfinity)
invert ((Finite 0), (Finite y)) = ((Finite (1 `div` y)), PosInfinity)
invert ((Finite x), (Finite 0)) = (NegInfinity, (Finite (1 `div` x)))
invert ((Finite x), (Finite y)) = ((Finite (1 `div` y)), (Finite (1 `div` x)))
invert (x,y) = error $ "It shouldnt reach here: " ++ (show x) ++ " " ++ (show y) -- Just to avoid non-exhaustive

-- Or operation, the minimum is always the minimum value a interval can take and
-- the maximum is infinity.
orInterval :: Itv -> Itv -> Itv
orInterval x y = orInterval' (normalizeInterval x) (normalizeInterval y)
  where
    orInterval' :: Itv -> Itv -> Itv
    orInterval' EmptyItv _ = EmptyItv
    orInterval' _ EmptyItv = EmptyItv
    orInterval' (Itv (a,_)) (Itv (c,_)) = Itv(minimum [a,c], PosInfinity)

-- And operation, the minimum value is negative infinity and maximum the highest
-- value one of the intervals can take.
andInterval :: Itv -> Itv -> Itv
andInterval x y = andInterval' (normalizeInterval x) (normalizeInterval y)
  where
    andInterval' :: Itv -> Itv -> Itv
    andInterval' _ EmptyItv = EmptyItv
    andInterval' EmptyItv _ = EmptyItv
    andInterval' (Itv (_,b)) (Itv (_,d)) = Itv(NegInfinity, maximum [b,d])


-- Lsh operation.
lshInterval :: Itv -> Itv -> Itv
lshInterval x y = lshInterval' (normalizeInterval x) (normalizeInterval y)
  where
    lshInterval' :: Itv -> Itv -> Itv
    lshInterval' EmptyItv _ = EmptyItv
    lshInterval' _ EmptyItv = EmptyItv
    lshInterval' (Itv (a,b)) (Itv (c,d)) = Itv(minimum [ac,ad,bc,bd], maximum [ac,ad,bc,bd])
      where 
        ac = lshift a c
        ad = lshift a d
        bc = lshift b c
        bd = lshift b d

-- Shift left operation, in the case the offset is negative it throws an error.
lshift :: ItvVal -> ItvVal -> ItvVal
-- -inf
lshift NegInfinity PosInfinity = NegInfinity
lshift NegInfinity (Finite x) = if x >= 0 then NegInfinity else error "Impossible to shift with negative offset"
lshift NegInfinity NegInfinity = error "Impossible to shift with negative offset"
-- +inf 
lshift PosInfinity NegInfinity = error "Impossible to shift with negative offset"
lshift PosInfinity (Finite x) = if x >= 0 then PosInfinity else error "Impossible to shift with negative offset"
lshift PosInfinity PosInfinity = PosInfinity
-- finite * ...
lshift (Finite _) PosInfinity = PosInfinity
lshift (Finite x) (Finite y) = if y >= 0 then (Finite (unsafeShiftL x y)) else error "Impossible to shift with negative offset"
lshift (Finite _) NegInfinity = error "Impossible to shift with negative offset" 

-- Rsh operation.
rshInterval :: Itv -> Itv -> Itv
rshInterval x y = rshInterval' (normalizeInterval x) (normalizeInterval y)
  where
    rshInterval' :: Itv -> Itv -> Itv
    rshInterval' EmptyItv _ = EmptyItv
    rshInterval' _ EmptyItv = EmptyItv
    rshInterval' (Itv (a,b)) (Itv (c,d)) = Itv(minimum [ac,ad,bc,bd], maximum [ac,ad,bc,bd])
      where 
        ac = rshift a c
        ad = rshift a d
        bc = rshift b c
        bd = rshift b d

-- Shift right operation, in the case the offset is negative it throws an error.
rshift :: ItvVal -> ItvVal -> ItvVal
-- -inf
rshift NegInfinity PosInfinity = (Finite 0)
rshift NegInfinity (Finite x) = if x >= 0 then NegInfinity else error "Impossible to shift with negative offset"
rshift NegInfinity NegInfinity = error "Impossible to shift with negative offset"
-- +inf 
rshift PosInfinity NegInfinity = error "Impossible to shift with negative offset"
rshift PosInfinity (Finite x) = if x >= 0 then PosInfinity else error "Impossible to shift with negative offset"
rshift PosInfinity PosInfinity = (Finite 0)
-- finite * ...
rshift (Finite _) PosInfinity = (Finite 0)
rshift (Finite x) (Finite y) = if y >= 0 then (Finite (unsafeShiftR x y)) else error "Impossible to shift with negative offset"
rshift (Finite _) NegInfinity = error "Impossible to shift with negative offset" 

-- Mod operation, if divisor can be negative then the result can take negative result, otherwise the minimum it takes is 0 
modInterval :: Itv -> Itv -> Itv
modInterval x y = modInterval' (normalizeInterval x) (normalizeInterval y)
  where 
    modInterval' :: Itv -> Itv -> Itv 
    modInterval' EmptyItv _ = EmptyItv
    modInterval' _ EmptyItv = EmptyItv
    modInterval' (Itv (NegInfinity, _)) (Itv (y1,y2)) = if y1 < (Finite 0) || y2 < (Finite 0) then Itv (NegInfinity, PosInfinity) else Itv (Finite 0, PosInfinity)
    modInterval' (Itv (_, PosInfinity)) (Itv (y1,y2)) = if y1 < (Finite 0) || y2 < (Finite 0) then Itv (NegInfinity, PosInfinity) else Itv (Finite 0, PosInfinity)
    modInterval' (Itv (Finite x1, Finite x2)) (Itv (y1,y2)) = if y1 < (Finite 0) || y2 < (Finite 0) then Itv (Finite (-v), Finite v) else Itv (Finite 0, Finite v) 
      where
        v = max (abs x1) (abs x2)
    modInterval' a b = error $ "Shouldnt reach here: " ++ show a ++ " " ++ show b

-- Xor operation, gets the highest value number of bits and returns the interval of values possible with those bits 
xorInterval :: Itv -> Itv -> Itv
xorInterval x y = xorInterval' (normalizeInterval x) (normalizeInterval y)
  where 
    xorInterval' :: Itv -> Itv -> Itv 
    xorInterval' EmptyItv _ = EmptyItv
    xorInterval' _ EmptyItv = EmptyItv
    xorInterval' (Itv (x1,x2)) (Itv (y1,y2)) = r
      where 
        maxi = maximum [abs' x1, abs' x2, abs' y1, abs' y2]
        r = case maxi of
              NegInfinity -> Itv (NegInfinity, PosInfinity) -- Cannot happen
              PosInfinity -> Itv (NegInfinity, PosInfinity)
              Finite 0 -> Itv (Finite 0, Finite 0)
              Finite a -> Itv ((Finite (-(ceiling $ logBase 2 $ (fromIntegral a :: Double)))), Finite (ceiling $ logBase 2 $ (fromIntegral a :: Double)))

abs' :: ItvVal -> ItvVal
abs' (NegInfinity) = PosInfinity
abs' (PosInfinity) = PosInfinity
abs' (Finite x) = Finite (abs x)

-- Arsh operation - Right shift with signed values.
arshInterval :: Itv -> Itv -> Itv
arshInterval x y = arshInterval' (normalizeInterval x) (normalizeInterval y)
  where
    arshInterval' :: Itv -> Itv -> Itv
    arshInterval' EmptyItv _ = EmptyItv
    arshInterval' _ EmptyItv = EmptyItv
    arshInterval' (Itv (a,b)) (Itv (c,d)) = Itv(minimum [ac,ad,bc,bd], maximum [ac,ad,bc,bd])
      where 
        ac = arshift a c
        ad = arshift a d
        bc = arshift b c
        bd = arshift b d

-- Arithmetic shift right operation, in the case the offset is negative it throws an error.
arshift :: ItvVal -> ItvVal -> ItvVal
-- -inf
arshift NegInfinity PosInfinity = (Finite (-1))
arshift NegInfinity (Finite x) = if x >= 0 then NegInfinity else error "Impossible to shift with negative offset"
arshift NegInfinity NegInfinity = error "Impossible to shift with negative offset"
-- +inf 
arshift PosInfinity NegInfinity = error "Impossible to shift with negative offset"
arshift PosInfinity (Finite x) = if x >= 0 then PosInfinity else error "Impossible to shift with negative offset"
arshift PosInfinity PosInfinity = (Finite 0)
-- finite * ...
arshift (Finite x) PosInfinity = if x >= 0 then (Finite 0) else (Finite (-1))
arshift (Finite x) (Finite y) = if y >= 0 then (Finite (shiftR x y)) else error "Impossible to shift with negative offset"
arshift (Finite _) NegInfinity = error "Impossible to shift with negative offset" 

------------------- Logical Itv Operations ------------------------

-- Equal operation [=] ([a,b],[c,d]) = ([a,b] /\ [c,d], [a,b] /\ [c,d]).
eqInterval :: Itv -> Itv -> (Itv, Itv)
eqInterval x y = eqInterval' (normalizeInterval x) (normalizeInterval y)
  where
    eqInterval' a b = (intersectionInterval a b, intersectionInterval a b)

-- Less than operation [<] ([a,b],[c,d]) = ([a,b] /\ [-inf, d-1], [a+1,+inf] /\ [c,d]).
ltInterval :: Itv -> Itv -> (Itv, Itv)
ltInterval a b = ltInterval' (normalizeInterval a) (normalizeInterval b)
  where
    ltInterval' :: Itv -> Itv -> (Itv, Itv)
    ltInterval' EmptyItv _ = (EmptyItv, EmptyItv)
    ltInterval' _ EmptyItv = (EmptyItv, EmptyItv)
    -- case (x1,_) < (_,y1)
    ltInterval' (Itv (Finite x1,x2)) (Itv (y1,Finite y2)) = 
      (intersectionInterval (Itv (Finite x1, x2)) (Itv (NegInfinity, Finite (y2-1))),
      intersectionInterval (Itv (Finite (x1 + 1), PosInfinity)) (Itv (y1, Finite y2)))
    -- case (x1,_) < (_,+inf) 
    ltInterval' (Itv (Finite x1,x2)) (Itv (y1,PosInfinity)) = 
      (intersectionInterval (Itv (Finite x1, x2)) (Itv (NegInfinity, PosInfinity)),
      intersectionInterval (Itv (Finite (x1 + 1), PosInfinity)) (Itv (y1, PosInfinity)))
    -- case (-inf,_) < (_,y1)
    ltInterval' (Itv (NegInfinity,x2)) (Itv (y1,Finite y2)) = 
      (intersectionInterval (Itv (NegInfinity, x2)) (Itv (NegInfinity, Finite (y2-1))),
      intersectionInterval (Itv (NegInfinity, PosInfinity)) (Itv (y1, Finite y2)))
    -- case (-inf,_) < (_,+inf)
    ltInterval' (Itv (NegInfinity,x2)) (Itv (y1,PosInfinity)) = 
      (intersectionInterval (Itv (NegInfinity, x2)) (Itv (NegInfinity, PosInfinity)),
      intersectionInterval (Itv (NegInfinity, PosInfinity)) (Itv (y1, PosInfinity)))
    -- case when one of the intervals is not correctly formatted
    ltInterval' x y = error $ "It shouldnt reach here: " ++ (show x) ++ " " ++ (show y) -- Just to avoid non-exhaustive

-- Less or equal than operation [<=] ([a,b],[c,d]) = ([a,b] /\ [-inf, d], [a,+inf] /\ [c,d]).
leqInterval :: Itv -> Itv -> (Itv, Itv)
leqInterval itv1 itv2 = leqInterval' (normalizeInterval itv1) (normalizeInterval itv2)
  where 
    leqInterval' :: Itv -> Itv -> (Itv, Itv)
    leqInterval' EmptyItv _ = (EmptyItv, EmptyItv)
    leqInterval' _ EmptyItv = (EmptyItv, EmptyItv)
    leqInterval' (Itv (x1,x2)) (Itv (y1,y2)) = 
      (intersectionInterval (Itv (x1,x2)) (Itv (NegInfinity, y2)),
      intersectionInterval (Itv (x1,PosInfinity)) (Itv (y1,y2)))

------------------- Widening & Narrowing ------------------------

--Performs widening operation in two intervals.
wideningInterval :: Itv -> Itv -> Itv
wideningInterval x EmptyItv = x
wideningInterval EmptyItv x = x
wideningInterval (Itv (x1,x2)) (Itv (y1, y2)) =
  Itv (x3,y3) 
  where
  x3 = if y1 < x1 then NegInfinity else x1
  y3 = if y2 > x2 then PosInfinity else x2

-- Widening of two states.
wideningState :: ItvState -> ItvState -> ItvState
wideningState = zipWith combine
  where
    combine (reg, itv1) (_, itv2) = (reg, wideningInterval itv1 itv2)

wideningMemory :: ItvMemory -> ItvMemory -> ItvMemory
wideningMemory = Map.intersectionWith wideningInterval

-- -- Performs narrowing operation in two intervals.
-- narrowingInterval :: Itv -> Itv -> Itv
-- narrowingInterval _ EmptyItv = EmptyItv
-- narrowingInterval EmptyItv _ = EmptyItv
-- narrowingInterval (Itv (x1,x2)) (Itv (y1, y2)) =
--   Itv (x3,y3) 
--   where
--   x3 = if x1 == NegInfinity then y1 else x1
--   y3 = if x2 == PosInfinity then y2 else x2

------------------- Itv Analysis ------------------------

-- Perform the interval analysis on a set of equations.
intervalAnalysis :: Equations -> ItvState -> ([ItvState], ItvMemory)
intervalAnalysis eq initialStateItv = fixpointItvAnalysis eqList state memory 1
    where
        eqList = Map.toList eq 
        state = replicate (length eqList) initialStateItv
        memory = Map.fromList [(i, EmptyItv) | i <- [0..511]]

-- Perform fixpoint computation for the analysis.
fixpointItvAnalysis :: [(Label, [(Label, Stmt)])] -> [ItvState] -> ItvMemory -> Int -> ([ItvState], ItvMemory)
fixpointItvAnalysis eq state mem i =
    if state == newState && mem == newMem' then (newState, newMem') else fixpointItvAnalysis eq newState newMem' i'
        where 
            (newState, newMem) = foldl (updateItvState i) (state, mem) eq 
            newMem' = if i `mod` 100 == 0 then wideningMemory mem newMem else newMem
            i' = i + 1


-- This function updates the state of a program point after it is analyzed.
updateItvState :: Int -> ([ItvState], ItvMemory) -> (Label, [(Label, Stmt)]) -> ([ItvState], ItvMemory)
updateItvState i (state, mem) (nodeIdx, eqs) = 
  ((before ++ [state'] ++ after), newMem)
  where
    (state', newMem) = processItvElement i Nothing state mem (nodeIdx, eqs)
    before = take nodeIdx state 
    after = drop (nodeIdx + 1) state

-- Process the equations for a specific node, returning the updated state.     
processItvElement :: Int -> Maybe ItvState -> [ItvState] -> ItvMemory -> (Label, [(Label, Stmt)]) -> (ItvState, ItvMemory)
processItvElement _ (Nothing) states mem (nodeIdx,[]) = (states !! nodeIdx, mem)
processItvElement _ (Just state) _ mem (_,[]) = (state, mem)
processItvElement i unionState states mem (currentNode, ((prevNode, stmt):es)) = 
    case unionState of
      Nothing -> processItvElement i (Just state') states newMem (currentNode, es)
      Just uState -> if i `mod` 100 == 0 
        then processItvElement i (Just (wideningState uState state')) states newMem (currentNode, es)
        else processItvElement i (Just (unionStt uState state')) states newMem (currentNode, es)
  where 
    prevState = (states !! prevNode)
    (state', newMem) = updateItvUsingStmt prevState mem stmt 

-- Update a node's state by analysing the the equation and then updating the interval(s) associated with 
-- the register(s) used in the equation. It also updates the memory value for memory handling operations.
updateItvUsingStmt :: ItvState -> ItvMemory -> Stmt -> (ItvState, ItvMemory)

-- Process Binary operations
updateItvUsingStmt state mem (AssignReg r (Bin e)) =     
  case lookup r state of 
      Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
      _ -> (state', mem)
  where
    newItv = processBinaryExpression state e
    state' = updateRegisterValue r newItv state

-- Process Mov operation
updateItvUsingStmt state mem (AssignReg r (Mv ri)) =
    case lookup r state of 
        Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
        _ -> (state', mem)
    where 
        newValue = normalizeInterval $ getRegisterImmediateInterval state ri
        state' = updateRegisterValue r newValue state

-- Process Unary operations
updateItvUsingStmt state mem (AssignReg r (Un e)) = 
  case lookup r state of 
      Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
      _ -> (state', mem)
  where
    newItv = processUnaryExpression state e
    state' = updateRegisterValue r newItv state

-- Process Store operations
updateItvUsingStmt state mem (StoreInMem r offset ri) = 
  case lookup r state of 
      Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
      _ -> (state, mem')
  where
    index = getRegisterInterval state r
    value = getRegisterImmediateInterval state ri
    indexOff = case offset of
      Just n -> addInterval index (constantInterval (fromIntegral n))
      Nothing -> index
    mem' = updateMemory mem value indexOff 

-- Process Load operation with register as index
updateItvUsingStmt state mem (LoadFromMemReg r r' offset) = 
    case lookup r state of 
      Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
      _ -> (state', mem)
  where
    index = getRegisterInterval state r'
    indexOff = case offset of
      Just n -> addInterval index (constantInterval (fromIntegral n))
      Nothing -> index
    itv = normalizeInterval $ getMemoryInterval mem indexOff
    state' = updateRegisterValue r itv state

-- Process Load operation with Imm as index
updateItvUsingStmt state mem (LoadFromMemImm r i) =   
  case lookup r state of 
      Nothing -> error ("Register: " ++ show r ++ " is not allowed to be used")
      _ -> (state', mem)
  where
    newItv = case Map.lookup (fromIntegral i) mem of
          Just itv -> normalizeInterval $ itv
          Nothing -> EmptyItv
    state' = updateRegisterValue r newItv state

-- Process conditional jumps
updateItvUsingStmt state mem (If cond _) = (processCondition state cond, mem)

-- Process Unconditional jump
updateItvUsingStmt state mem (CallOp _) = (state, mem)

-- Process Call operation
updateItvUsingStmt state mem (Goto _) = (state, mem)

------------- Functions related to states handling ------------------------

-- Process binary operations, by utilizing the arithmetic operations above.
processBinaryExpression :: ItvState -> BinaryExp -> Itv
processBinaryExpression state e = 
    case e of
      AddOp r ri -> processBinaryExpression' addInterval r ri state
      SubOp r ri -> processBinaryExpression' subInterval r ri state
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
    LeOp r -> normalizeInterval $ getRegisterInterval state r -- Identity
    BeOp r -> normalizeInterval $ getRegisterInterval state r -- Identity
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
    Equal r ri ->  processCondition' eqInterval (R r) ri state
    -- Less than operation
    LessThan r ri ->  processCondition' ltInterval (R r) ri state
    -- Less or equal than operation
    LessEqual r ri -> processCondition' leqInterval (R r) ri state
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

-- Function that updates the memory using an interval as index. 
-- It uses the interval as index, i.e. updates each memory cell corresponding to
-- every index in the interval with the value.
updateMemory :: ItvMemory -> Itv -> Itv -> ItvMemory
updateMemory me a b = updateMemory' me (normalizeInterval a) (normalizeInterval b)
  where 
    updateMemory' :: ItvMemory -> Itv -> Itv -> ItvMemory
    updateMemory' mem _ (EmptyItv) = mem 
    updateMemory' mem value (Itv (NegInfinity, PosInfinity)) = foldl (\m i -> Map.insert i value m) mem [0..511]
    updateMemory' mem value (Itv (NegInfinity, (Finite y))) = 
      if y <= 0 
        then Map.insert y value mem
        else foldl (\m i -> Map.insert i value m) mem [0..y] 
    updateMemory' mem value (Itv ((Finite x), PosInfinity)) = 
      if x < 511
          then foldl (\m i -> Map.insert i value m) mem [x..511] 
          else Map.insert x value mem
    updateMemory' mem value (Itv ((Finite x), (Finite y))) = foldl (\m i -> Map.insert i value m) mem [x..y] 
    updateMemory' _ value x = error $ "It shouldnt reach here: " ++ (show value) ++ " " ++ (show x) -- Just to avoid non-exhaustive pattern

-- Function that takes an interval with indexes and return the biggest possible interval from the
-- values mapped by the indexes in memory.
getMemoryInterval :: ItvMemory -> Itv -> Itv
getMemoryInterval me a = getMemoryInterval' me (normalizeInterval a)
  where
    getMemoryInterval' :: ItvMemory -> Itv -> Itv
    getMemoryInterval' _ EmptyItv = EmptyItv
    getMemoryInterval' mem (Itv (NegInfinity, PosInfinity)) = itv
      where
        intervals = mapMaybe (`Map.lookup` mem) [0..511]
        itv = normalizeInterval $ Itv (findLowerBound intervals, findUpperBound intervals)
    getMemoryInterval' mem (Itv (NegInfinity, (Finite y))) = itv
      where
        intervals =   
          if y <= 0 
            then mapMaybe (`Map.lookup` mem) [y] 
            else mapMaybe (`Map.lookup` mem) [0..y] 
        itv = normalizeInterval $ Itv (findLowerBound intervals, findUpperBound intervals)
    getMemoryInterval' mem (Itv ((Finite x), PosInfinity)) = itv
        where
          intervals =   
            if x < 511
                then mapMaybe (`Map.lookup` mem) [x..511] 
                else mapMaybe (`Map.lookup` mem) [x] 
          itv = normalizeInterval $ Itv (findLowerBound intervals, findUpperBound intervals)
    getMemoryInterval' mem (Itv ((Finite x), (Finite y))) = itv
      where
        intervals = mapMaybe (`Map.lookup` mem) [x..y] 
        itv = normalizeInterval $ Itv (findLowerBound intervals, findUpperBound intervals)
    getMemoryInterval' _ x = error $ "It shouldnt reach here: " ++ (show x) -- Just to avoid non-exhaustive pattern

-- Filter the lower bound and returns the smallest
-- In the case it is an Empty interval I return the greatest possible 
-- value (PosInfinity), it is only selected if the only possibility is 
-- the result being EmptyItv.
findLowerBound :: [Itv] -> ItvVal
findLowerBound  = minimum . map extractLowerBound
  where
    extractLowerBound :: Itv -> ItvVal
    extractLowerBound EmptyItv = PosInfinity
    extractLowerBound (Itv (Finite x, _)) = (Finite x)
    extractLowerBound (Itv (NegInfinity, _)) = NegInfinity
    extractLowerBound x = extractLowerBound (normalizeInterval x)

-- Filter the upper bound and returns the greatest
-- In the case it is an Empty interval I return the lowest possible 
-- value (NegInfinity), it is only selected if the only possibility is 
-- the result being EmptyItv.
findUpperBound :: [Itv] -> ItvVal
findUpperBound  = maximum . map extractUpperBound
  where
    extractUpperBound :: Itv -> ItvVal
    extractUpperBound EmptyItv = NegInfinity
    extractUpperBound (Itv (_, Finite y)) = (Finite y)
    extractUpperBound (Itv (_, PosInfinity)) = PosInfinity
    extractUpperBound x = extractUpperBound (normalizeInterval x)

-- Union of two states.
unionStt :: ItvState -> ItvState -> ItvState
unionStt = zipWith combine
  where
    combine (reg, itv1) (_, itv2) = (reg, unionInterval itv1 itv2)
