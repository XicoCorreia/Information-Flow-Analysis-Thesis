module Main where

import IFA.Types
import IFA.Equations
import IFA.Analysis
import IFA.Cfg
import IFA.IntervalAnalysis

import qualified System.Environment as Sys
import qualified Data.Set as Set
import qualified Data.Map as Map
import Data.Graph.Dom as Dom
import Text.Printf

import Ebpf.Asm
import Ebpf.AsmParser
import Ebpf.Display ()

------------------- Update environment for the analysis ------------------------

-- Parse input to Register
parseReg :: String -> Either String Reg
parseReg "r0"  = Right (Reg 0)
parseReg "r1"  = Right (Reg 1)
parseReg "r2"  = Right (Reg 2)
parseReg "r3"  = Right (Reg 3)
parseReg "r4"  = Right (Reg 4)
parseReg "r5"  = Right (Reg 5)
parseReg "r6"  = Right (Reg 6)
parseReg "r7"  = Right (Reg 7)
parseReg "r8"  = Right (Reg 8)
parseReg "r9"  = Right (Reg 9)
parseReg "r10" = Right (Reg 10)
parseReg r     = Left $ "Input" ++ r ++ " caused the error, only registers 0 to 10 are allowed in eBPF programs"


-- Update initial state with secret registers
updateRegisterInState :: [Reg] -> (Reg, SecurityLevel) -> (Reg, SecurityLevel)
updateRegisterInState secrets (r, seclvl) 
  | r `elem` secrets = (r, High)
  | otherwise = (r, seclvl)

------------------- Initial Environment for the analysis ------------------------

initialState :: State
initialState = [
    (Reg 0, Low), (Reg 1, High), (Reg 2, Low), 
    (Reg 3, Low), (Reg 4, Low), (Reg 5, Low), 
    (Reg 6, Low), (Reg 7, Low), (Reg 8, Low), 
    (Reg 9, Low), (Reg 10, Low)]

-- Initialize state with every register associated with an empty interval.
initialStateItv :: ItvState
initialStateItv = [
    (Reg 0, EmptyItv), (Reg 1, Itv (Finite 0, Finite 5)), (Reg 2, EmptyItv), 
    (Reg 3, EmptyItv), (Reg 4, EmptyItv), (Reg 5, EmptyItv), 
    (Reg 6, EmptyItv), (Reg 7, EmptyItv), (Reg 8, EmptyItv), 
    (Reg 9, EmptyItv), (Reg 10, EmptyItv)]

------------------- Perform analysis and generate dotfile with cfg ------------------------
main :: IO ()
main = do
  args <- Sys.getArgs
  if length args < 2
    then do
      putStrLn "Usage:"
      putStrLn "- Run information flow analysis and visualize cfg:\n <EBPF_FILE> <DOT_FILE> [secret1 secret2]"
      putStrLn "- Example: cabal run ebpf-cfg -- examples/doWhile.asm graphs/doWhile.dot r1 r2 r3"
    else
      -- Get arguments
      let ebpfFile = args !! 0
          dotFile  = args !! 1
          secretRegs = map parseReg (drop 2 args)
      in do  
      case sequence secretRegs of
        -- Case where there is an error parsing the registers
        Left err -> do
          putStrLn "Some sort of error occurred while parsing:"
          print err
        -- Update state with valid registers
        Right regs -> do
          let updatedState = map (updateRegisterInState regs) initialState
          -- Run ebpf-tools
          printf $ "\nRun Information Flow Analysis on " ++ ebpfFile ++ "\n"
          res <- parseFromFile ebpfFile
          case res of
            -- Case where there is an error parsing the program
            Left err -> do
              putStrLn "Some sort of error occurred while parsing:"
              print err
            -- Create CFG, equations and run the analysis
            Right prog -> 
              let 
                cfg' = cfg prog
                equations = cfgToEquations cfg' (Map.empty)
                (itvStates, _) = intervalAnalysis equations initialStateItv
                edgesList = [(from, to) | (from, _, to) <- Set.toList cfg']
                graphDom = ((length equations), Dom.fromEdges edgesList) 
                (states, memory, context) = informationFlowAnalysis graphDom equations updatedState itvStates
                conditions = Set.toList $ Set.map fst context
                dependencies = concatMap snd (Set.toList context)
                edges = cfgToDot $ cfg prog
              in do
              -- Print analysis output  
              printf "\nEquations:\n"
              putStrLn $ formatMap equations
              printf "\nItv Analysis:\n"
              mapM_  (\(index,lst) -> putStrLn (show index ++ ": " ++ show lst)) (zip ([0..] :: [Int]) itvStates) 
              printf "\nFinal states:\n"  
              mapM_  (\(index,lst) -> putStrLn (show index ++ ": " ++ show lst)) 
                (zip ([0..] :: [Int]) states) 
              printf "\nHigh Memory:\n"
              putStrLn $ show ([ (i,s) | (i,s) <- Map.toList memory, s == High])
              printf "\nHigh Context:\n"
              putStrLn $ show context
              -- Write dot File
              writeFile dotFile (dotPrelude ++
                        edges ++
                        (markHighContextNodes prog (conditions, dependencies)) ++ "}")
              printf "\nVisualised the CFG in %s\n" dotFile
              printf $ "\n-----------------------Analysis completed-----------------------\n"
