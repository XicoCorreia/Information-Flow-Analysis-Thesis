import ControlFlowTest
import Test.Tasty (defaultMain, testGroup)

main :: IO ()
main = 
  defaultMain $
    testGroup
      "Analysis tests"
      [ ControlFlowTest.tests 
      ]