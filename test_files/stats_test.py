import angr
import claripy

def main():
    p = angr.Project('./matrix', main_opts={'base_addr': 0}, load_options={"auto_load_libs": False})

    index = claripy.BVS('index', 8 * 15)
    value = claripy.BVS('value', 8 * 6)

    state = p.factory.entry_state(args=['stats', index, value])
    simgr = p.factory.simgr(state)

    simgr.run()


if __name__ == '__main__':
    main()
