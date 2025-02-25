module IFA.Equations (cfgToEquations, formatMap) where

import qualified Data.Map as Map
import qualified Data.Set as Set
import Data.List (intercalate)

import IFA.Types
import Ebpf.Asm as E

-- Converts the edges of a Control Flow Graph (CFG) into a set of equations.
-- Each edge in the CFG is mapped to an equation representing the flow of control.
cfgToEquations :: CFG -> Equations -> Equations
cfgToEquations cfg eq = foldr edgeToEquation eq (Set.toList cfg)

-- Converts a single edge from the CFG into an equation.
edgeToEquation :: (Label, Trans, Label) -> Equations -> Equations
edgeToEquation (from, NonCF i, to) = addEquation from to (opToStmt i)
edgeToEquation (from, Assert cmp r ir, to) = addEquation from to (If (assertToCond cmp r ir) to)
edgeToEquation (from, Unconditional, to) = addEquation from to (Goto to)

-- Converts a conditional jump (Jcmp) into an appropriate condition (Cond).
assertToCond :: Jcmp -> Reg -> RegImm -> Condition
assertToCond cmp r ri = case cmp of
  Jeq -> Equal r ri
  Jne -> NotEqual r ri
  Jgt -> GreaterThan r ri
  Jge -> GreaterEqual r ri
  Jlt -> LessThan r ri
  Jle -> LessEqual r ri
  Jsgt -> GreaterThan r ri
  Jsge -> GreaterEqual r ri
  Jslt -> LessThan r ri
  Jsle -> LessEqual r ri
  Jset -> Equal r ri

-- Converts a given instruction (e.g., binary operation, store) into an equivalent statement (Stmt).
opToStmt :: Instruction -> Stmt
opToStmt (Binary _ Mov r ri) = AssignReg r (Mv ri)
opToStmt (Binary _ op r ri) = AssignReg r $ Bin $ case op of
  Add -> AddOp r ri
  Sub -> SubOp r ri
  Mul -> MulOp r ri
  Div -> DivOp r ri
  Or  -> OrOp  r ri
  And -> AndOp r ri
  Lsh -> LshOp r ri
  Rsh -> RshOp r ri
  Mod -> ModOp r ri
  Xor -> XorOp r ri
  Arsh -> ArshOp r ri
opToStmt (Unary _ op r) = AssignReg r $ Un $ case op of
  Neg -> NegOp r
  Le -> LeOp r
  Be -> BeOp r
opToStmt (Store _ r off ri) =  StoreInMem r off ri
opToStmt (Call n) = CallOp (fromIntegral n)
opToStmt (Load _ r1 r2 off) = LoadFromMemReg r1 r2 off
opToStmt (LoadImm r i) = LoadFromMemImm r i
opToStmt (LoadMapFd r i) = LoadFromMemImm r i
opToStmt (LoadAbs _ i) = LoadFromMemImm (Reg 0) i 
opToStmt (LoadInd _ r i) = LoadFromMemReg (Reg 0) r (Just i)
opToStmt i = error $ "Instruction not implemented yet: " ++ (show i)

-- Adds a new equation (statement) to the equation list for the given node.
addEquation :: Label -> Label -> Stmt -> Equations -> Equations
addEquation prev node stmt eqs =
  let currentList = Map.findWithDefault [] node eqs
      newList = (prev, stmt) : currentList
  in Map.insert node newList eqs

-- Function for better visualization of the equations
formatMap :: Equations -> String
formatMap m = intercalate "\n" $ map formatEntry (Map.toList m)
  where
    formatEntry (key, valueList) = show key ++ " -> " ++ show valueList