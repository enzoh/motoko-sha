echo PATH = $PATH
echo vessel @ `which vessel`

echo
echo == Build.
echo

dfx start --background
dfx canister create --all
dfx build

echo
echo == Test.
echo

dfx canister install --all --mode=reinstall
dfx canister call test run '()'
