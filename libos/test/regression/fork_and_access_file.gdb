set breakpoint pending on
set pagination off
set backtrace past-main on

# We want to check what happens in the child process after fork()
set follow-fork-mode child

# Cannot detach after fork because of some bug in SGX version of GDB (GDB would segfault)
set detach-on-fork off

tbreak fork
commands
  echo BREAK ON FORK\n

  shell echo "WRITING NEW CONTENT IN FORK_AND_ACCESS_FILE_TESTFILE" > fork_and_access_file_testfile

  tbreak die_or_inf_loop
  commands
    echo EXITING GDB WITH A GRAMINE ERROR\n
    quit
  end

  tbreak exit
  commands
    echo EXITING GDB WITHOUT A GRAMINE ERROR\n
    quit
  end

  continue
end

run
