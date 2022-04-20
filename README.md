# 20-21_saluhe
Tecnologías empleadas:<br>
> - Pedersen Committment como esquema de compromiso  
> - Miller Rabin como test de primalidad
> - HMAC como PRF'
> - Funcion de Dodis-Yampolsky como PRF
> - Gelberg et al. como prueba de conocimiento cero
<br>

<h2> Esquema del protocolo</h2>
<img src="https://latex.codecogs.com/svg.image?\inline&space;\\r'_{u}&space;\leftarrow&space;\textit{SHA-256&space;}(0\left|&space;\right|r_{u})\\\rho_{u}\leftarrow&space;\textit{SHA-256&space;}(1\left|&space;\right|r_{u})\\(C,Open)&space;\leftarrow&space;\textit{Pedersen&space;}(r'_{u},\rho_{u})\\s'&space;\leftarrow&space;\textit{SHA-256&space;}(2\left|&space;\right|r_{u})&space;\\\overset{C}{\rightarrow}\\\\\overset{r_{CA}}{\leftarrow}\\\\s\leftarrow&space;r'_{u}\bigoplus&space;\textit{SHA-256&space;}(r_{CA})\\\left&space;(&space;\left&space;(&space;a_{\gamma}&space;\right&space;)_{\gamma=1}^{j}&space;,&space;i&space;\right&space;)\leftarrow&space;\textit{Algorithm&space;2&space;with&space;random&space;string&space;HMAC}&space;(s',\gamma,1^{\left|&space;r_{w}&space;\right|})\\&space;" />

