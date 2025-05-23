module ControlFlowTest where

import IFA.Analysis
import IFA.Equations
import IFA.Types
import IFA.Cfg
import IFA.IntervalAnalysis

import Ebpf.Asm
import Ebpf.AsmParser

import Test.Tasty
import Test.Tasty.HUnit
import Control.Exception (try, SomeException, evaluate)
import qualified Data.Set as Set
import qualified Data.Map as Map
import Data.Graph.Dom as Dom

tests :: TestTree
tests = testGroup "eBPF Analysis HandWritten Tests" (map createTest examplePrograms)

createTest :: (String, ([State], Memory)) -> TestTree
createTest (ebpfFile,(expStates, expMem)) = 
    testCase ("Testing " ++ ebpfFile) $ do
        res <- parseFromFile ("examples/" ++ ebpfFile)
        case res of
            Left err -> 
                assertFailure $ "Error parsing program: " ++ show err
            Right prog -> 
                if null expStates
                    then do
                        result <- try (evaluate (informationFlowAnalysis graphDom equations initialState itv)) 
                            :: IO (Either SomeException SystemState)
                        case result of
                            Left _  -> return () 
                            Right _ -> assertFailure $ show result
                    else do
                        let (states, memory, _) = informationFlowAnalysis graphDom equations initialState itv
                        states @?= expStates
                        memory @?= expMem
                where
                    cfg' = cfg prog
                    equations = cfgToEquations cfg' Map.empty
                    edgesList = [(from, to) | (from, _, to) <- Set.toList cfg']
                    graphDom = (length equations, Dom.fromEdges edgesList)
                    (itv,_) = intervalAnalysis equations initialStateItv


initialState :: State
initialState = [
    (Reg 0, Low), (Reg 1, High), (Reg 2, Low), 
    (Reg 3, Low), (Reg 4, Low), (Reg 5, Low), 
    (Reg 6, Low), (Reg 7, Low), (Reg 8, Low), 
    (Reg 9, Low), (Reg 10, Low)]

initialStateItv :: ItvState
initialStateItv = [
    (Reg 0, EmptyItv), (Reg 1, Itv (Finite 0, Finite 5)), (Reg 2, EmptyItv), 
    (Reg 3, EmptyItv), (Reg 4, EmptyItv), (Reg 5, EmptyItv), 
    (Reg 6, EmptyItv), (Reg 7, EmptyItv), (Reg 8, EmptyItv), 
    (Reg 9, EmptyItv), (Reg 10, EmptyItv)]

memoryInitial :: Memory
memoryInitial = Map.fromList [(i, Low) | i <- [0..511]]


examplePrograms :: [(String, ([State], Memory))]
examplePrograms =
  [ ("doWhile.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], memoryInitial))
    ,
    ("whileLoop.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], memoryInitial))
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
        ], memoryInitial))
                ,
        ("whileLoopLow.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,Low),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], memoryInitial))
        ,
        ("ifStatementNested.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,High),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,High),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,High),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,High),(Reg 9,Low),(Reg 10,Low)]
        ], memoryInitial))
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
        ], memoryInitial))
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
        ], memoryInitial))
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
        ], memoryInitial))
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
        ], memoryInitial))
        ,
        ("loadFromReg.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,High),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3, High),(Reg 4,High),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Map.fromList [if i <= 5 then (i, High) else (i, Low) | i <- [0..511]]))
        ,
        ("loadFromImm.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Map.fromList [if i >= 9 && i <=14 then (i, High) else (i, Low) | i <- [0..511]]))
        ,
        ("memoryError.asm", ([], Map.empty))
        ,
        ("largeMemoryIndex.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Map.fromList [(i, High) | i <- [0..511]]))
        ,
        ("largeMemoryIndex.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,High),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Map.fromList [(i, High) | i <- [0..511]]))
        ,
        ("memoryOpLoop.asm", (
        [ [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,Low),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        , [(Reg 0,High),(Reg 1,High),(Reg 2,Low),(Reg 3,Low),(Reg 4,Low),(Reg 5,Low),(Reg 6,Low),(Reg 7,Low),(Reg 8,Low),(Reg 9,Low),(Reg 10,Low)]
        ], Map.fromList [if i >= 10 && i <=13 then (i, High) else (i, Low) | i <- [0..511]]))
  ]