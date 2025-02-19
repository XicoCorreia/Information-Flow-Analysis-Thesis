module IFA.Types where

import Data.Set as Set
import Data.Map as Map
import Ebpf.Asm

------------------- CFG Types ------------------------
data Trans =
    NonCF Instruction  -- No jumps, or exit
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

data BinaryOp =
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
  | MovOp RegImm
    deriving (Show)

data UnaryOp = 
    NegOp Reg
  | LeOp Reg
  | BeOp Reg
    deriving (Show)

data Cond = 
      Equal Reg RegImm
    | NotEqual Reg RegImm
    | LessThan Reg RegImm
    | LessEqual Reg RegImm
    | GreaterThan Reg RegImm
    | GreaterEqual Reg RegImm
    deriving (Show)

data Stmt =
    AssignReg Reg BinaryOp
  | ModifyReg Reg UnaryOp
  | StoreInMem Reg (Maybe MemoryOffset) RegImm
  | LoadFromMemReg Reg Reg (Maybe MemoryOffset)
  | LoadFromMemImm Reg Imm 
  | If Cond Label
  | Goto Label
  | CallOp Int
    deriving (Show)

type Equations = Map Label [(Label, Stmt)]

------------------- Analysis Types ------------------------
data SecurityLevel = High | Low 
  deriving (Eq, Show)

type State = [(Reg, SecurityLevel)]
type Memory = SecurityLevel
type HighSecurityContext = Set.Set (Label,[Label]) 

type SystemState = ([State], Memory, HighSecurityContext)