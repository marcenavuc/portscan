# Portscan
Автор: Аверченко Марк (КБ-201)

## Requirements
* You need sudo rights

## Start
```sudo python3 -m port_scanner [-h] [-t] [-u] [-p PORT PORT] host```

## Example: Scanning tcp ports
```python -m port_scanner localhost -t```

**Output**
 
```
TCP 53 DOMAIN
TCP 80 HTTP
TCP 631 IPP
TCP 953 
TCP 3306 MYSQL
TCP 5432 POSTGRESQL
TCP 6379 
TCP 6942 
TCP 33060 
TCP 34450 
TCP 43537 
TCP 55214 
TCP 57621 
TCP 63342 
```
