import angr
import claripy

def main():
    p = angr.Project('./mat_mult', main_opts={'base_addr': 0}, load_options={"auto_load_libs": False})

    row_begin = claripy.BVS('row_b', 8 * 4)
    row_end = claripy.BVS('row_e', 8 * 4)
    col_begin = claripy.BVS('col_b', 8 * 4)
    col_end = claripy.BVS('col_e', 8 * 4)

    state = p.factory.entry_state(args=['matrix', row_begin, row_end, col_begin, col_end])
    simgr = p.factory.simgr( state)

    simgr.run()


if __name__ == '__main__':
    main()
