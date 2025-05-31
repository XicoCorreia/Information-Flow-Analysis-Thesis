module IFA.Types where

import Data.Set as Set
import Data.Map as Map
import Ebpf.Asm

------------------- CFG Types ------------------------
data Trans =
    NonCF Instruction
  | Unconditional
  | Assert Jcmp Reg RegImm
  deriving (Show, Eq, Ord)

type Label = Int
type LabeledProgram = [(Int, Instruction)]
type CFG = Set (Label, Trans, Label)

------------------- Equations Types ------------------------

-- newtype Reg = Reg Int deriving (Eq, Show, Ord, Data)
-- type Imm = Int64
-- data RegImm = R Reg | Imm Imm deriving (Eq, Show, Ord, Data)
-- type Offset = Int64
-- type MemoryOffset = Offset

data Exp =
    Bin BinaryExp
  | Un UnaryExp
  | Mv RegImm
    deriving (Show)

data BinaryExp =
    AddOp Reg RegImm
  | SubOp Reg RegImm
  | MulOp Reg RegImm 
  | DivOp Reg RegImm
  | OrOp  Reg RegImm
  | AndOp Reg RegImm
  | LshOp Reg RegImm
  | RshOp Reg RegImm
  | ModOp Reg RegImm
  | XorOp Reg RegImm
  | ArshOp Reg RegImm
    deriving (Show)

data UnaryExp = 
    NegOp Reg
  | LeOp Reg
  | BeOp Reg
    deriving (Show)

data Condition = 
      Equal Reg RegImm
    | NotEqual Reg RegImm
    | LessThan Reg RegImm
    | LessEqual Reg RegImm
    | GreaterThan Reg RegImm
    | GreaterEqual Reg RegImm
    deriving (Show)

data Stmt =
    AssignReg Reg Exp
  | StoreInMem Reg (Maybe MemoryOffset) RegImm
  | LoadFromMemReg Reg Reg (Maybe MemoryOffset)
  | LoadFromMemImm Reg Imm 
  | If Condition Label
  | Goto Label
  | CallOp Int
    deriving (Show)

type Equations = Map Label [(Label, Stmt)]

------------------- Analysis Types ------------------------
data SecurityLevel = High | Low 
  deriving (Eq, Show)

type State = [(Reg, SecurityLevel)]
type Memory = Map.Map Int SecurityLevel
type HighSecurityContext = Set.Set (Label,[Label]) 

type SystemState = ([State], Memory, HighSecurityContext)

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

-- Memory that maps an interval to each index
type ItvMemory = Map.Map Int Itv