import angr
import claripy

def main():
    p = angr.Project('../akshaysg_tests/simple', load_options={"auto_load_libs": False})

    test = claripy.BVS('arg1', 8 * 8)
    length = claripy.BVS('arg2', 8 * 8)

    state = p.factory.entry_state(args=[test, length], add_options={"SYMBOLIC_WRITE_ADDRESSES"})
    simgr = p.factory.simgr(state)

    simgr.explore(find=lambda s: b"Woah" in s.posix.dumps(1))

    if simgr.found:
        print("found!")
        s = simgr.found[0]
        print(s.solver.eval(test))
        print(s.solver.eval(length))
    else:
        print("no paths found")

    return


if __name__ == '__main__':
    main()
