module ControlFlowTest where

import IFA.Analysis
import IFA.Equations
import IFA.Types
import IFA.Cfg

import Ebpf.Asm
import Ebpf.AsmParser

import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.Set as Set
import qualified Data.Map as Map
import Data.Graph.Dom as Dom

tests :: TestTree
tests = testGroup "eBPF Analysis HandWritten Tests" (map createTest examplePrograms)

createTest :: (String, ([State], SecurityLevel)) -> TestTree
createTest (ebpfFile,(expStates, expMem)) = 
    testCase ("Testing " ++ ebpfFile) $ do
        res <- parseFromFile ("examples/" ++ ebpfFile)
        case res of
            Left err -> 
                assertFailure $ "Error parsing program: " ++ show err
            Right prog -> do
                states @?= expStates
                memory @?= expMem
                where
                    cfg' = cfg prog
                    equations = cfgToEquations cfg' Map.empty
                    edgesList = [(from, to) | (from, _, to) <- Set.toList cfg']
                    graphDom = (length equations, Dom.fromEdges edgesList)
                    (states, memory, _) = informationFlowAnalysis graphDom equations initialState


initialState :: State
initialState = [
    (Reg 0, Low), (Reg 1, High), (Reg 2, Low), 
    (Reg 3, Low), (Reg 4, Low), (Reg 5, Low), 
    (Reg 6, Low), (Reg 7, Low), (Reg 8, Low), 
    (Reg 9, Low), (Reg 10, Low)]

examplePrograms :: [(String, ([State], SecurityLevel))]
examplePrograms =
  [ ("doWhile.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Low))
    ,
    ("whileLoop.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Low))
        ,
    ("ifStatement.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Low))
        ,
    ("nestedIfLoop.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Low))
        ,
    ("nestedWhiles.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Low))
        ,
    ("seqWhiles.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Low))
        ,
    ("doWhileIfNested.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,High),(Reg 5,High),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Low))
  ]