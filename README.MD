The `.conf` files under `./confs` should be placed at `$SDE_INSTALL/share/p4/targets/tofino`.

After compiling dfa.p4 and halfsiphash.p4, put the output directory in `$SDE/install/share/tofinopd/EXAMPLE_NAME`.

Then in `$SDE`, run the following:
`./run_tofino_model.sh -p dfa --arch tofino`
`./run_switchd.sh -p dfa --arch tofino`
`./run_p4_tests.sh -p dfa --arch tofino`

Replace `dfa` with `halfsiphash` to test the hashing device.
