# Reporte Técnico: CVE-2026-31431 "Copy Fail"

## ¿Qué es el bug?
CVE-2026-31431, conocido como "Copy Fail", es una vulnerabilidad de lógica
en el subsistema criptográfico del kernel Linux (crypto/algif_aead.c).
Existe desde 2017 y permite a cualquier usuario local sin privilegios
obtener acceso root.

## ¿Cómo funciona el exploit?
El exploit usa tres componentes del kernel:
1. AF_ALG: interfaz de sockets para criptografía del kernel
2. authencesn: módulo de autenticación AEAD
3. splice(): llamada al sistema para transferir datos entre buffers

El bug estaba en la función _aead_recvmsg(). Usaba req->src == req->dst
(mismo scatterlist para entrada y salida), lo que permitía escribir
4 bytes controlados directamente en el page cache de /usr/bin/su
(un binario setuid-root) sin tocar el disco.

Al ejecutar su después, el kernel cargaba la versión corrupta en
memoria y se obtenía una shell root.

## ¿Por qué es peligroso?
- No requiere privilegios especiales
- Funciona en Ubuntu, RHEL, Amazon Linux y SUSE sin modificaciones
- El exploit tiene solo 732 bytes de Python
- No deja rastros en disco

## Mitigación temporal (Hito 3)
Se deshabilitó el módulo algif_aead con:
  rmmod algif_aead
  echo "install algif_aead /bin/false" > /etc/modprobe.d/block-algif.conf

Trade-off: aplicaciones que usen AEAD autenticado vía AF_ALG dejan
de funcionar (por ejemplo, algunas implementaciones de WireGuard
y herramientas de cifrado que usan la API de crypto del kernel).

## Parche permanente (Hito 4)
Se modificó crypto/algif_aead.c en la función _aead_recvmsg().
El fix cambia el segundo argumento de aead_request_set_crypt():

  Antes (vulnerable):
  aead_request_set_crypt(..., tsgl_src, areq->first_rsgl.sgl.sgt.sgl, ...);

  Después (parcheado):
  aead_request_set_crypt(..., tsgl_src, rsgl_src, ...);

Esto mantiene TX SGL y RX SGL separados (out-of-place), eliminando
la posibilidad de escribir en el page cache de binarios setuid.

## Verificación
- Kernel vulnerable (6.12.0): exploit exitoso, uid=0(root)
- Kernel parcheado (7.1.0-rc3+): exploit falla con "su: Module is unknown"
