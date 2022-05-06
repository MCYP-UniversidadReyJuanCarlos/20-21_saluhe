# 20-21_saluhe
Tecnologías empleadas:<br>
> - Pedersen Committment como esquema de compromiso  
> - Miller Rabin como test de primalidad
> - HMAC como PRF'
> - Funcion de Dodis-Yampolsky como PRF
> - Golberg et al. como prueba de conocimiento cero

<br>
<h2> Esquema del protocolo</h2>

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

