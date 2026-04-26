set -l script_dir (realpath (dirname (status filename)))
set -l tool_path "$script_dir/ifn-tools.py"

if test -f "$script_dir/.venv/bin/activate.fish"
    source "$script_dir/.venv/bin/activate.fish"
else
    echo "Warning: .venv/bin/activate.fish not found in $script_dir"
end

function ifn-tools --inherit-variable tool_path
    python $tool_path $argv
end

complete -e ifn-tools
complete -e "$tool_path"

#set -l comp_logic (python "$tool_path" --show-completion fish)

# We swap the filename for our command name 'ifn-tools' 
# and ensure the internal logic uses the absolute path
#set -l fixed_logic (string replace -a "ifn-tools.py" "$tool_path" "$comp_logic" | string replace "complete --command $tool_path" "complete --command ifn-tools")

#eval $fixed_logic
