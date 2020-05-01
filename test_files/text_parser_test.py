import angr
import claripy

def main():
    p = angr.Project('./matrix', main_opts={'base_addr': 0}, load_options={"auto_load_libs": False})

    text = claripy.BVS('index', 8 * 1000)

    state = p.factory.entry_state(args=['text_parser', text])
    simgr = p.factory.simgr(state)

    simgr.run()


if __name__ == '__main__':
    main()
