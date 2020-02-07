import angr
import claripy

def main():
    p = angr.Project('../akshaysg_tests/simple', load_options={"auto_load_libs": False})

    test = claripy.BVS('arg1', 8 * 4)
    length = claripy.BVS('arg2', 8 * 4)

    state = p.factory.entry_state(args=[test, length], add_options={"SYMBOLIC_WRITE_ADDRESSES"})
    simgr = p.factory.simgr(state)

    simgr.explore(find=lambda s: b"Test" in s.posix.dumps(1))

    if simgr.found:
        print("found!")
        print("{}".format(simgr.found[0].state.se.any_int(test)))
    else:
        print("no paths found")

    return


if __name__ == '__main__':
    main()
