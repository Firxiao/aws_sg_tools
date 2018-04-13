## aws security group tools

This repository is used to store some useful tools to modify aws security groups.

requirement: _python2.x or 3.x_

## Features
- _add_multi_sg_rules.py_ : 
  - interactive input
  - selectable environment via profile
  - search source and destination sg via name
  - support multiple source or destination 
  - review rules

## How to use 

- Install requirements modules

```bash
git clone https://github.com/Firxiao/aws_sg_tools.git
cd aws_sg_tools
pip install requirements.txt
```
- modify config.yml according to your environment

```yaml
region:
   - env: env1
   - env: env2
```

- run it then follow the menu to add your sg rules.

```bash
python add_multi_sg_rules.py
``` 

