set breakpoint pending on
set pagination off
set backtrace past-main on

# We want to check what happens in the child process after fork()
set follow-fork-mode child

# Cannot detach after fork because of some bug in SGX version of GDB (GDB would segfault)
set detach-on-fork off



break adversary_save_file
commands
python
from shutil import copyfile
from gdb_helper import adversary_do
adversary_do(lambda external_path, external_path_saved, external_path2: copyfile(external_path, external_path_saved))
end

continue
end


break adversary_reset_file
commands
python
from shutil import move
from gdb_helper import adversary_do
adversary_do(lambda external_path, external_path_saved, external_path2: move(external_path_saved, external_path))
end

continue
end


break adversary_reset_file_as
commands
python
from shutil import move
from gdb_helper import adversary_do
adversary_do(lambda external_path, external_path_saved, external_path2: move(external_path_saved, external_path2))
end

continue
end


break adversary_delete_file
commands
python
from pathlib import Path
from gdb_helper import adversary_do
adversary_do(lambda external_path, external_path_saved, external_path2: Path.unlink(external_path))
end

continue
end


break die_or_inf_loop
commands
  echo EXITING GDB WITH A GRAMINE ERROR\n
  quit
end

break exit
commands
  echo EXITING GDB WITHOUT A GRAMINE ERROR\n
  quit
end

run
