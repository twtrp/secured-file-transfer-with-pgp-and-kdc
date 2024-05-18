import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from clientApp import *

sender = sys.argv[1]
recipient = sys.argv[2]

SendFile(sender, recipient)