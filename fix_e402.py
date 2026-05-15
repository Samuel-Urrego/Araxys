import os
import re

for root, _, files in os.walk('src'):
    for file in files:
        if file.endswith('.py'):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # The regex looks for from __future__ followed by any newlines, then the docstring.
            # We want to swap them.
            new_content = re.sub(r'^(from __future__ import annotations\n+)(\"\"\"[\s\S]*?\"\"\"\n+)', r'\2\1', content)
            
            if new_content != content:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(new_content)
