# GENERACIÓN VERIFICABLE DE CLAVES CRIPTOGRÁFICAS
Los protocolos criptográficos se diseñan comúnmente bajo el supuesto de que las diferentes partes de este tienen acceso a la aleatoriedad perfecta (es decir, uniforme). Sin embargo, las fuentes aleatorias utilizadas en implementaciones prácticas rara vez cumplen con esta suposición y proporcionan solo un flujo de bits con un cierto "nivel de aleatoriedad". La calidad de los números aleatorios determina directamente la solidez de la seguridad de los sistemas que los utilizan.

Cuando la generación de claves criptográficas (por ejemplo, para firma digital) se hace maliciosamente, es posible “sustituir” valores presumiblemente elegidos al azar por otros, con distintos fines (vulnerar la seguridad de la firma, insertar canales encubiertos de comunicación.). En consecuencia, en este proyecto se lleva a cabo una implementación de un esquema RSA con aleatoriedad verificable, documentada por el protocolo genérico de claves descrito por [Blazy et al](https://eprint.iacr.org/2020/294.pdf).

## Indice
> - [Características](#características)
> - [Como ejecutar](#como-ejecutar)
> - [Uso básico](#uso-básico)
> - [Documentación de desarrollo](#documentación-de-desarrollo)
> - [Arquitectura](#arquitectura)
> - [Entorno para desarrollo y ejecución](#entorno-para-desarrollo-y-ejecución)
> - [Bibliografía](#bibliografía)

### Características
Proyecto desarrollado en lenguaje Python, concretamente en la version Python 3.10.4.

### Como ejecutar
Ejecutar el archivo ejecutable **dist/20-21_saluhe.exe** disponible en este proyecto. La ejecucion del mismo generara, en esa misma carpeta, un fichero de salida.

### Uso básico
Obtencion de colecciones de primos generados con cierta aleatoriedad verificable.

### Documentación de desarrollo
En esta seccion se proporciona el esquema del protocolo asi como el listado de las diversas tecnologías empleadas en el mismo.

Tecnologías empleadas en el protocolo implementado son las siguientes:<br>
> - [Pedersen Committment](#pedersen-commitment-scheme) como esquema de compromiso  
> - [Miller Rabin](#miller-rabin-prime-test) como test de primalidad
> - [HMAC](#prf-hmac) como PRF'
> - Funcion de [Dodis-Yampolsky](#prf-dodis-yampolsky) como PRF. Usada en  el [Algoritmo 2](#algoritmo-2) referenciado en el protocolo
> - [Golberg et al.](#nizk-golberg-et-al) como prueba de conocimiento cero.

El esquema del protocolo es el siguiente:

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
    
    
   #### PRF Dodis Yampolsky
  <img src="https://latex.codecogs.com/svg.image?\\\left\{1...d&space;\right\}\textit{&space;d}\epsilon\mathbb{N}&space;\textit{&space;}\overset{f}{\rightarrow}&space;\textit{z&space;}\epsilon&space;\textit{G&space;de&space;orden&space;primo&space;t,&space;con&space;generador&space;g}\\\textit{Siendo&space;x}\epsilon&space;Z_{t}^{*}\textit{&space;la&space;clave&space;secreta}\\&space;f\equiv&space;V_{x}:\left\{1...d&space;\right\}\rightarrow&space;G\\&space;\textit{Siendo&space;el&space;mensaje&space;m:&space;}&space;V_{x}(m)=g^{\frac{1}{x&plus;m}}&space;\textit{&space;donde&space;x&plus;m}\neq&space;0&space;\textit{&space;modt&space;y&space;}1_{G}\textit{&space;en&space;otro&space;caso}" title="https://latex.codecogs.com/svg.image?\\\left\{1...d \right\}\textit{ d}\epsilon\mathbb{N} \textit{ }\overset{f}{\rightarrow} \textit{z }\epsilon \textit{G de orden primo t, con generador g}\\\textit{Siendo x}\epsilon Z_{t}^{*}\textit{ la clave secreta}\\ f\equiv V_{x}:\left\{1...d \right\}\rightarrow G\\ \textit{Siendo el mensaje m: } V_{x}(m)=g^{\frac{1}{x+m}} \textit{ donde x+m}\neq 0 \textit{ modt y }1_{G}\textit{ en otro caso}" />
    
  
  #### PRF HMAC
  
  Dada una entrada 'text':
  <table> 
   <tr>
      <th>Pasos</th>
      <th>Descripcion de los pasos</th>
    </tr>
    <tr>
      <td>1</td>
      <td>Si la longitud de K=B, entonces K0= K. Salto al paso 4<td>
    </tr>
    <tr>
      <td>2</td>
      <td>Si la longitud de K>B, calculo el hash de K para obtener un string de L Bytes, despues añade al final (B-L) ceros para crear un string de B-Bytes K0. Es decir, K0 = H(K) || 00...00. Salto al paso 4</td>
    </tr>
    <tr>
      <td>3</td>
      <td>Si la longitud de K es menor que B, añade B-K ceros para crear un string K0 de longitud B-Bytes. Es decir, si la longitud de K es 20 bytes y la longitud de B es 64 bytes, entonces se añadiran 44 bytes cero x’00’ para formar K0</td>
    </tr>
    <tr>
      <td>4</td>
      <td>K0 ⊕ ipad</td>
    </tr>
    <tr>
      <td>5</td>
      <td>Añadir el parametro de entrada text: (K0 ⊕ ipad) || text </td>
    </tr>
    <tr>
      <td>6</td>
      <td>Se aplica la funcion hash a la salida del paso 5: H((K0 ⊕ ipad) || text) </td>
    </tr>
    <tr>
      <td>7</td>
      <td>K0 ⊕ opad</td>
    </tr>
    <tr>
      <td>8</td>
      <td>Se añade el resultado del paso 7 al resultado del paso 6: (K0 ⊕ opad) || H((K0 ⊕ ipad) || text)</td>
    </tr>
    <tr>
      <td>9</td>
      <td>Se aplica el hash al resultado del paso 8: H((K0 ⊕ opad )|| H((K0 ⊕ ipad) || text))</td>
    </tr>
  </table> 
  
  
  #### Miller Rabin Prime Test
  
Input : n (n is the number to be tested for primality) 
<br>
Output : whether n is prime or not
<br>

  <table>
  <tr>
    <td>
      <img src="https://latex.codecogs.com/svg.image?\\\textit{n-1&space;=&space;2}^{s}d\textit{&space;&space;d}&space;\epsilon&space;N,&space;\textit{&space;&space;s}\epsilon&space;N\\\textit{Choose&space;a&space;random&space;integer&space;a&space;where&space;}2\leq&space;a\leq&space;n-2\\\\X\equiv&space;a^{d}(modn)\\&space;\textit{If&space;X}\equiv\pm&space;1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;probably&space;prime'}\\\textit{If&space;s=1}\equiv\pm&space;1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;de&space;finitely&space;not&space;prime'}\\&space;\\r=1\\\\\textbf{Step&space;3}\\&space;X\equiv&space;a^{2^{r}d}(modn)\\&space;\textit{If&space;X}\equiv&space;1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;de&space;finitely&space;not&space;prime'}\\\textit{If&space;X}\equiv&space;-1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;probably&space;prime'}\\&space;r=r&plus;1\\\textit{If&space;r&space;!=&space;s-1}\\\indent&space;\textit{then&space;go&space;to&space;Step&space;3}\\\\X\equiv&space;a^{2^{s-1}d}(modn)\\&space;\textit{If&space;X}\not\equiv&space;&space;-1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;de&space;finitely&space;not&space;prime'}\\\textit{If&space;X}\equiv&space;-1(modn)\\\indent&space;\textit{return&space;'n&space;is&space;probably&space;prime'}&space;" />
   </td>
  </tr>
  </table>
  
  
  #### NIZK Golberg et al
  El esquema de la prueba de conocimiento cero se encuentra descrito en el anexo C (Detailed Specification for the NIZK of Permutations over Zn) del documento [Efficient noninteractive certification of RSA moduli and beyond.](https://par.nsf.gov/servlets/purl/10189824)  
  
  #### Pedersen Commitment Scheme
 <img src="https://latex.codecogs.com/svg.image?\\\textit{Dado&space;un&space;parametro&space;de&space;seguridad&space;k:}\\\textit{setup}(1^{k})\textit{&space;genera&space;dos&space;primos&space;publicos:}\\\indent&space;p\rightarrow&space;\textit{k-bit&space;largo}\\\indent&space;p\rightarrow&space;\textit{k-bit&space;largo&space;y&space;donde&space;q&space;divide&space;a&space;p-1}\\&space;\indent\textit{Dos&space;generadores&space;g&space;y&space;h,&space;obtenidos&space;del&space;grupo&space;G&space;de&space;orden&space;q}&space;\\&space;\textit{Commit}&space;\\&space;\indent&space;m&space;\epsilon&space;Z_{q}&space;\\&space;\indent&space;\textit{CommitEl&space;committer&space;escoge&space;un&space;valor&space;aleatorio&space;r}\epsilon&space;Z_{q}\textit{&space;denominado&space;Opening,&space;y&space;calcula&space;el&space;compromiso&space;c&space;}(c&space;\epsilon&space;Z_{p}^{*})\\&space;\indent&space;\indent&space;Com(m)=g^{m}h^{r}\textit{&space;mod&space;p&space;}\Rightarrow&space;\textit{Devuelve&space;r,c}\\&space;\\&space;&space;" title="https://latex.codecogs.com/svg.image?\\\textit{Dado un parametro de seguridad k:}\\\textit{setup}(1^{k})\textit{ genera dos primos publicos:}\\\indent p\rightarrow \textit{k-bit largo}\\\indent p\rightarrow \textit{k-bit largo y donde q divide a p-1}\\ \indent\textit{Dos generadores g y h, obtenidos del grupo G de orden q} \\ \textit{Commit} \\ \indent m \epsilon Z_{q} \\ \indent \textit{CommitEl committer escoge un valor aleatorio r}\epsilon Z_{q}\textit{ denominado Opening, y calcula el compromiso c }(c \epsilon Z_{p}^{*})\\ \indent \indent Com(m)=g^{m}h^{r}\textit{ mod p }\Rightarrow \textit{Devuelve r,c}\\ \\ " />

  
  #### Algoritmo 2  
Necesita PrimeTestW, enteros T; b; e, Dodis-Yampolsky PRF, seed s. 
<br>
Devuelve una coleccion de numeros pseudo-aleatorios a y el entero i. Este entero i apunta al primer numero primo de la coleccion y el segundo numero primo esta en  la ultima posicion de esta coleccion devuelta. En caso de no encontrar 2 numeros primos, i vale -1.
<br>
  
<table>
  <tr>
    <td>
      <img src="https://latex.codecogs.com/svg.image?\\&space;\textit{ctr,i,j&space;}\leftarrow&space;0&space;\\\\\textit{while&space;ctr&space;}<&space;2\textit{&space;and&space;j&space;}<\textit{T&space;do}\\\indent&space;\textit{j&space;}\leftarrow&space;\textit{j&plus;1}&space;\\\indent&space;a_{j}\leftarrow&space;\textit{Dodis-Yampolsky(s,j)}&space;\\\\\indent&space;\textit{if&space;PrimeTest}_{W}\textit{&space;(b,e,a}_{j}\textit{)&space;then}&space;\\\indent&space;\indent&space;\textit{if&space;ctr&space;=&space;0&space;then}\\\indent&space;\indent&space;\indent&space;\textit{i}\leftarrow&space;j&space;&space;\\\indent&space;\indent&space;\textit{endif}\\\indent&space;\indent&space;\textit{ctr}\leftarrow&space;ctr&plus;1&space;&space;\\\indent&space;\textit{endif}\\\\\textit{if&space;ctr}<2&space;\textit{&space;then}\\\indent&space;\textit{return&space;}\left&space;(&space;(a_{\gamma})_{\gamma&space;=&space;1}^{j},&space;\textit{-1}&space;\right&space;)&space;\\\textit{else}\\\indent&space;\textit{return&space;}\left&space;(&space;(a_{\gamma})_{\gamma&space;=&space;1}^{j},&space;i&space;\right&space;)&space;\\&space;\textit{endif}&space;" />
    </td>
  </tr>
 </table>  
      

### Arquitectura

#### Arquitectura del codigo
<img src="https://github.com/MCYP-UniversidadReyJuanCarlos/20-21_saluhe/blob/main/Arq.svg" />

#### Estructura del proyecto

> 20-21_saluhe
>> **src**
>>>  **main.py** Fichero con el principal codigo de los hilos que representan usuario y CA. Asi como la inicializacion de los mismos.
>>>  
>>>  **algorithm_2.py** Implementacion del algoritmo 2 descrito.
>>>  
>>>  **dodis_yampolsky.py** Implementacion de la PRF de Dodis-Yampolsky descrita.
>>>  
>>>  **exception_text_to_file.py** Clase cuya funcionalidad es la escritura de excepciones en el fichero de salida generado.
>>>  
>>>  **fastModularExp.py** Implementacion del algoritmo de exponenciacion modular rapida.
>>>  
>>>  **golberg.py** Definicion de la prueba de conocimiento cero de Golberg et al. descrita.
>>>  
>>>  **hashSha256.py** Implementacion del algoritmo de hash.
>>>  
>>>  **hmac_c.py** Implementacion del esquema HMAC.
>>>  
>>>  **millerRabin_primetest.py** Implementacion del test de primalidad de Miller Rabin descrito.
>>>  
>>>  **models.py** Clase para la definicion de tipos auxiliares.
>>>  
>>>  **nonce.py** Metodos necesarios para la generacion de valores NONCE.
>>>  
>>>  **perdersen.py** Implementacion del esquema de compromiso de Pedersen.
>>>  
>>>  **sieve_of_erastosthenes.py** Implementacion del algoritmo de sieve of eratosthenes, encargado de buscar la coleccion de numeros primos desde 2 a n, siendo n un parametro de entrada.
>>>  
>> **Ficheros de salida** Carpeta con ejemplos de salidas de la aplicacion.
>> 
>> **Documentation** Carpeta con los principales documentos usados durante la fase de investigacion.


### Entorno para desarrollo y ejecución

* Visual Studio Code como IDE para el desarrollo de este proyecto.
  - Es necesario instalar Python y Pylance para el uso de este IDE.
* Las librerias necesarias son las siguientes: pyasn1, rsa.asn1, Crypto, gmpy2, pkcs1
    - **pyasn1**    py -m pip install pyasn1
    - **rsa.asn1**  py -m pip install rsa
    - **Crypto**    py -m pip install pycryptodome
    - **gmpy2**     py -m pip install gmpy2
    - **pkcs1**     py -m pip install pkcs1
* **Al instalar las librerias es posible que necesite cerrar y volver a abrir el IDE para que el error de falta de dependencias desaparezca**

Para la creacion del fichero exe con todas las dependencias:
* (Si no se dispone del modulo pyinstaller, es necesario ejecutar lo siguiente: - **pyinstaller**     py -m pip install PyInstaller)
* **python -O -m PyInstaller -F "\<ruta-del-proyecto\>"\src\main.py -n "\<nombre-del-ejecutable-final\>"**
* La opcion -F del comando se usa para la encapsulacion de las dependencias en un solo fichero ejecutable.

### Bibliografía

*  O. BLAZY, P. TOWA y D. VERGNAUD, «[Public-key generation with verifiable randomness](https://eprint.iacr.org/2020/294.pdf)» International Conference on the Theory and Application of Cryptology and Information Security, pp. BLAZY, Olivier; TOWA, Patrick; VERGNAUD, Damien. . Springer, Cham, 2020. p. 97-127., 2020.  
*  K. CONRAD, «[The Miller–Rabin Test](https://kconrad.math.uconn.edu/blurbs/ugradnumthy/millerrabin.pdf)» Encyclopedia of Cryptography and Security, 2011.  
*  S. R. L. S. O. &. B. F. Goldberg, «[Efficient noninteractive certification of RSA moduli and beyond.](https://par.nsf.gov/servlets/purl/10189824)» International Conference on the Theory and Application of Cryptology and Information Security, pp. 700-727.  
*  J. M. TURNER, «[The keyed-hash message authentication code (hmac)](http://nvlpubs.nist.gov/nistpubs/fips/nist.fips.198-1.pdf)» Federal Information Processing Standards Publication, pp. 1-13.  
* Y. DODIS y A. YAMPOLSKIY, «[A verifiable random function with short proofs and keys](https://link.springer.com/content/pdf/10.1007/978-3-540-30580-4_28.pdf)» International Workshop on Public Key Cryptography, pp. 416-431, 2005.  
*  D. &. L. J. Demirel, «[How to securely prolong the computational bindingness of pedersen commitments.](https://eprint.iacr.org/2015/584.pdf)» Cryptology ePrint Archive, 2015.  

