# Key generation with verifiable randomness 
Project description

## Index:
> - [Features](#features)
> - [How to run](#how-to-run)
> - [Basic usage](#basic-usage)
> - [Development documentation](#development-documentation)
> - [Architecture](#architecture)
> - [Prepare development and execution environment](#prepare-development-and-execution-environment)

### Features

### How to run

### Basic usage

### Development documentation

### Architecture

### Prepare development and execution environment


Tecnologías empleadas en el protocolo implementado son las siguientes:<br>
> - Pedersen Committment como esquema de compromiso  
> - Miller Rabin como test de primalidad
> - HMAC como PRF'
> - Funcion de Dodis-Yampolsky como PRF. Usada en  el [Algoritmo 2](#algoritmo-2) referenciado en el protocolo
> - Golberg et al. como prueba de conocimiento cero

## Índice:
> - [Esquema del protocolo](#esquema-del-protocolo)
> - [Algoritmo 2](#algoritmo-2)
> - [PRF Dodis Yampolsky](#prf-dodis-yampolsky)
> - [PRF HMAC](#prf-hmac)
> - [Miller Rabin Prime Test](#miller-rabin-prime-test)
> - [NIZK Golberg et al](#nizk-golberg-et-al)
> - [Pedersen Commitment Scheme](#pedersen-commitment-scheme)

### Esquema del protocolo
<table>
  <tr>
    <th>USER'S ACTIONS</th>
    <th></th>
    <th>CA'S ACTIONS</th>
  </tr>
  <tr>
    <td><img src="https://latex.codecogs.com/svg.image?\textit{U(pp,e;}r_{u})\\"/></td>
    <td></td>
    <td><img src="https://latex.codecogs.com/svg.image?\textit{CA(pp;}r_{CA})"/></td>
  </tr>
  <tr>
    <td>
          <img src="https://latex.codecogs.com/svg.image?\\r'_{u}&space;\leftarrow&space;\textit{SHA-256&space;}(0\left|&space;\right|r_{u})\\\rho_{u}\leftarrow&space;\textit{SHA-256&space;}(1\left|&space;\right|r_{u})\\(C,Open)&space;\leftarrow&space;\textit{Pedersen&space;}(r'_{u},\rho_{u})\\s'&space;\leftarrow&space;\textit{SHA-256&space;}(2\left|&space;\right|r_{u})&space;" /></td>
    <td></td>
    <td></td>
  </tr> 
  <tr>
    <td></td>
    <td><img src="https://latex.codecogs.com/svg.image?\\\overset{C}{\rightarrow}\\\\\overset{r_{CA}}{\leftarrow}\\\\" /></td>
    <td></td>
  </tr>
  <tr>
    <td><img src="https://latex.codecogs.com/svg.image?\\s\leftarrow&space;r'_{u}\oplus&space;\textit{SHA-256&space;}(r_{CA})\\\left&space;(&space;\left&space;(&space;a_{\gamma}&space;\right&space;)_{\gamma=1}^{j}&space;,&space;i&space;\right&space;)\leftarrow&space;\textit{Algorithm&space;2&space;with&space;random&space;string&space;HMAC}&space;(s',\gamma,1^{\left|&space;r_{w}&space;\right|})\\p\leftarrow&space;a_{i}&space;\\q\leftarrow&space;a_{j}&space;\\N\leftarrow&space;p\ast&space;q&space;\\\pi_{W}\leftarrow&space;\Pi_{W}&space;\textit{&space;Golberg&space;et&space;al.&space;proof&space;that&space;(N,e)&space;}\epsilon&space;\textit{&space;}L_{w}&space;\textit{&space;with&space;random&space;string&space;HMAC}(s',\textit{j&plus;2},1^{\left|&space;r_{\pi_{w}}&space;\right|})\\\\&space;" /></td>
    <td></td>
    <td></td>
  </tr>
  <tr>
    <td><img src="https://latex.codecogs.com/svg.image?\textit{Erase&space;all&space;variables&space;but&space;N,&space;e,&space;i,&space;p,&space;q,}&space;\left&space;(&space;a_{\gamma&space;}&space;\right&space;)_{\gamma&space;\neq&space;i,j},&space;\pi&space;\textit{&space;and&space;}\pi_{W}\\" /></td>
    <td><img src="https://latex.codecogs.com/svg.image?\\\xrightarrow[i,\left&space;(&space;a_{\gamma&space;}&space;\right&space;)_{\gamma&space;\neq&space;i,j}]{\textit{(N,e),}\pi,\pi_{W}}\\\\" /></td>
    <td>
      <img src="https://latex.codecogs.com/svg.image?\\s''\leftarrow&space;\textit{HMAC(}r_{CA})\\\Pi_{W}\textit{.Verf(pp}_{\pi_{W}},\textit{(N,e),}\pi_{W})\questeq&space;1\\" /> 
    </td>
  </tr>
  <tr>
    <td><img src="https://latex.codecogs.com/svg.image?\textit{return&space;((N,e),(p,q,e))}\\" /></td>
    <td></td>
    <td><img src="https://latex.codecogs.com/svg.image?\textit{return&space;(N,e)}\\" /></td>
  </tr>
  </table>
  
  ### Algoritmo 2
  
  Necesita PrimeTestW, enteros T; b; e, Dodis-Yampolsky PRF, seed s. 
  <br>
  Devuelve una coleccion de numeros pseudo-aleatorios a y el entero i. Este entero i apunta al primer numero primo de la coleccion y el segundo numero primo esta en la ultima posicion de esta coleccion devuelta. En caso de no encontrar 2 numeros primos, i vale -1.
  
  <table>
  <tr>
    <td>
      <img src="https://latex.codecogs.com/svg.image?\\&space;\textit{ctr,i,j&space;}\leftarrow&space;0&space;\\\\\textit{while&space;ctr&space;}<&space;2\textit{&space;and&space;j&space;}<\textit{T&space;do}\\\indent&space;\textit{j&space;}\leftarrow&space;\textit{j&plus;1}&space;\\\indent&space;a_{j}\leftarrow&space;\textit{Dodis-Yampolsky(s,j)}&space;\\\\\indent&space;\textit{if&space;PrimeTest}_{W}\textit{&space;(b,e,a}_{j}\textit{)&space;then}&space;\\\indent&space;\indent&space;\textit{if&space;ctr&space;=&space;0&space;then}\\\indent&space;\indent&space;\indent&space;\textit{i}\leftarrow&space;j&space;&space;\\\indent&space;\indent&space;\textit{endif}\\\indent&space;\indent&space;\textit{ctr}\leftarrow&space;ctr&plus;1&space;&space;\\\indent&space;\textit{endif}\\\\\textit{if&space;ctr}<2&space;\textit{&space;then}\\\indent&space;\textit{return&space;}\left&space;(&space;(a_{\gamma})_{\gamma&space;=&space;1}^{j},&space;\textit{-1}&space;\right&space;)&space;\\\textit{else}\\\indent&space;\textit{return&space;}\left&space;(&space;(a_{\gamma})_{\gamma&space;=&space;1}^{j},&space;i&space;\right&space;)&space;\\&space;\textit{endif}&space;" />
    </td>
  </tr>
  
  </table>
  
  ### PRF Dodis Yampolsky
  
  
  
  ### PRF HMAC
  
  
  
  ### Miller Rabin Prime Test
  
  Input : n (n is the number to be tested for primality) 
  <br>
  Output : whether n is prime or not
  
  <table>
  <tr>
    <td>
      <img src="https://latex.codecogs.com/svg.image?\\\textit{n-1&space;=&space;2}^{s}d\textit{&space;&space;d}&space;\epsilon&space;N,&space;\textit{&space;&space;s}\epsilon&space;N\\\textit{Choose&space;a&space;random&space;integer&space;a&space;where&space;}2\leq&space;a\leq&space;n-2\\\\X\equiv&space;a^{d}(modn)\\&space;\textit{If&space;X}\equiv\pm&space;1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;probably&space;prime'}\\\textit{If&space;s=1}\equiv\pm&space;1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;de&space;finitely&space;not&space;prime'}\\&space;\\r=1\\\\\textbf{Step&space;3}\\&space;X\equiv&space;a^{2^{r}d}(modn)\\&space;\textit{If&space;X}\equiv&space;1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;de&space;finitely&space;not&space;prime'}\\\textit{If&space;X}\equiv&space;-1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;probably&space;prime'}\\&space;r=r&plus;1\\\textit{If&space;r&space;!=&space;s-1}\\\indent&space;\textit{then&space;go&space;to&space;Step&space;3}\\\\X\equiv&space;a^{2^{s-1}d}(modn)\\&space;\textit{If&space;X}\not\equiv&space;&space;-1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;de&space;finitely&space;not&space;prime'}\\\textit{If&space;X}\equiv&space;-1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;probably&space;prime'}&space;" />
   </td>
  </tr>
  </table>
  
  
  ### NIZK Golberg et al
  
  
  
  ### Pedersen Commitment Scheme
  
  
  
