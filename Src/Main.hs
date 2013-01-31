{-# LANGUAGE OverloadedStrings #-}
module Main where

--import System.Console.GetOpt
import System.Environment
import Control.Applicative ((<$>))
import Control.Monad
import qualified Crypto.PubKey.RSA as RSA (generate)
import qualified Crypto.PubKey.RSA.PSS as RSA (sign, verify, defaultPSSParamsSHA1)
import Data.Certificate.KeyRSA
import System.IO
import System.Exit
import System.Directory (getAppUserDataDirectory, doesFileExist, setPermissions, readable, emptyPermissions)
import System.FilePath ((</>))
import qualified Crypto.Random.AESCtr as RNG

import qualified Data.ByteString as B
import qualified Data.ByteString.Lazy as L

data SignatureHeader = SignatureHeader
    { author         :: String
    , email          :: String
    , keyFingerprint :: B.ByteString
    }

pathToSigningKey :: IO FilePath
pathToSigningKey = do
    dir <- getAppUserDataDirectory "cabal"
    return (dir </> "signing-key")


mainVerify :: [String] -> IO ()
mainVerify args = do
    case args of
        [manifestFile,signatureFile] -> do
                let publicKey = "abc.pub"
                pub      <- either error id . decodePublic <$> L.readFile publicKey
                mFile    <- B.readFile manifestFile
                signData <- B.readFile signatureFile
                let verified = RSA.verify RSA.defaultPSSParamsSHA1 pub mFile signData
                if verified
                    then putStrLn "Success" >> exitSuccess
                    else putStrLn "Failure" >> exitFailure
        _ -> error "arguments"

mainSign :: [String] -> IO ()
mainSign args = do
    rng <- RNG.makeSystem
    case args of
        [manifestFile] -> do sigKeyPath <- pathToSigningKey
                             pv         <- either error snd . decodePrivate <$> L.readFile sigKeyPath
                             mFile      <- B.readFile manifestFile
                             case fst $ RSA.sign rng Nothing RSA.defaultPSSParamsSHA1 pv mFile of
                                Left err -> error $ show err
                                Right s  -> B.writeFile (manifestFile ++ ".sign") s
        _ -> return ()

writeFileSecure path content = do
    exi <- doesFileExist path
    when exi $ error "path already exists, cannot overwrite"
    B.writeFile path ""
    -- setPermissions path $ emptyPermissions { readable = True }
    -- FIXME reduce permission now
    B.writeFile path bcontent
    where 
          bcontent = B.concat $ L.toChunks content

mainInit :: [String] -> IO ()
mainInit _ = do
    rng <- RNG.makeSystem
    let ((pub,priv),_) = RSA.generate rng (4096`div`8) 0x10001
    sigKeyPath <- pathToSigningKey
    writeFileSecure sigKeyPath (encodePrivate (pub,priv))
    return ()

usage :: Maybe String -> IO ()
usage e = hPutStrLn stderr $ unlines (maybe [] (\x -> [x, ""]) e ++ usageLines)
    where
          usageLines =
            [ "usage: cabal-signature cmd [opts]"
            , ""
            , "   init    initialize signature infrastructure"
            , "   sign    sign a manifest"
            , "   verify  verify the manifest signature"
            ]

main :: IO ()
main = do
    args <- getArgs
    case args of
        []             -> usage Nothing
        "verify":rargs -> mainVerify rargs
        "sign":rargs   -> mainSign rargs
        "init":rargs   -> mainInit rargs
        cmd:_          -> usage $ Just ("error: unknown command : " ++ cmd)
