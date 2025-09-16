from abstract_utilities import *
imports = "/server/etc/nginx/sites-available/clownworld/servers/443/imports.conf"              
includes = read_from_file(imports)
read_ls = []
for line in includes.split('\n'):
    if line:
        if not line.startswith('#'):
            line = line.split('include ')[-1]
            path = eatAll(f"/server{line}",[' ','\n','\t',';'])
            content = read_from_file(path)
            read_ls.append(content)
contents = '\n'.join(read_ls)
input(contents)
