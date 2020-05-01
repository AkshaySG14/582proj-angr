import angr
import claripy

def main():
    p = angr.Project('./simple', main_opts={'base_addr': 0}, load_options={"auto_load_libs": False})

    index = claripy.BVS('index', 8 * 4)

    state = p.factory.entry_state(args=['simple', index])
    simgr = p.factory.simgr(state)

    simgr.explore(find=lambda sm: b"Correct Input" in sm.posix.dumps(1))

    if simgr.found:
        print("found!")
        s = simgr.found[0]
        print(s.solver.eval(index, cast_to=bytes))
    else:
        print("no paths found")

    return


if __name__ == '__main__':
    main()
