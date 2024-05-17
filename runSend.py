import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

sender = sys.argv[1]
file = sys.argv[2]
recipient = sys.argv[3]

SendFile(sender, file, recipient)