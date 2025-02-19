module ControlFlowTest where

import Test.Tasty
import Test.Tasty.HUnit   

import IFA.Analysis
import IFA.Equations
import IFA.Types
import IFA.Cfg
    



tests :: TestTree
tests =
    testGroup 
    "Tests"
    [ testCase "1" $ assertBool "Non-empty list" (null [])
    ]

