import angr
import claripy

def main():
    p = angr.Project('./matrix', main_opts={'base_addr': 0}, load_options={"auto_load_libs": False})

    row = claripy.BVS('row', 8 * 4)
    col = claripy.BVS('col', 8 * 4)

    state = p.factory.entry_state(args=['matrix', row, col])
    simgr = p.factory.simgr(state)

    simgr.explore(find=lambda sm: b"Correct Input" in sm.posix.dumps(1))

    if simgr.found:
        print("found!")
        s = simgr.found[0]
        print(s.solver.eval(row, cast_to=bytes))
        print(s.solver.eval(col, cast_to=bytes))
    else:
        print("no paths found")

    return


if __name__ == '__main__':
    main()
