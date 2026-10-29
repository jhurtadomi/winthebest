---
title: "Mi Experiencia con la CRTP - 2026"
pubDatetime: 2026-03-13T10:00:00Z
draft: false
tags:
  - "CRTP"
  - "Active Directory"
  - "Red Team"
  - "Pentesting"
description: "Mi camino, anécdotas, preparación y metodología para aprobar la certificación Certified Red Team Professional (CRTP) de Altered Security."
heroImage: "/assets/images/posts/CRTP/portada_crtp.png"
---
## **ANÉCDOTA**

Hace como un año, estaba en el séptimo ciclo de Ingeniería de Sistemas sintiéndome en un callejón sin salida. Con el título cada vez más cerca, ni siquiera tenía un currículum definido; si bien es cierto que había realizado muchos proyectos de software y gestión, honestamente, no me llenaban. Había tenido un primer roce con la Seguridad Informática y Linux en un curso de la facultad y me había enganchado, pero en ese momento lo veía más como un sueño lejano que como una carrera real.

Todo cambió una noche, en una conversación por Instagram con una amiga. Ella intentaba venderme unos productos (jajaja), pero terminamos hablando del futuro. Me preguntó a qué pensaba dedicarme y solté lo que llevaba tiempo guardándome: "No estoy seguro, pero el Ethical Hacking me llama mucho la atención y no sé qué hacer". En ese momento, yo estaba a punto de dar los primeros pasos para mi tesis e investigaciones enfocadas en Software; sentía que iba en contra de lo que realmente quería. No es que no me guste desarrollar es muy chévere, pero todos tenemos algo que nos engancha más.

Ella me comentó que tenía un amigo ya egresado que se dedicaba a eso. Le habló de mí, nos puso en contacto y empezamos a hablar. Él me aconsejó, me dio la motivación que necesitaba y fue el puente hacia lo que vendría después.

Este amigo me consiguió una cita con el Director de mi Escuela. Yo sabía que él era un referente en el área, así que fui al día siguiente con los nervios propios de quien busca una oportunidad, pero con las ideas claras por primera vez. Le comenté mis ganas de aprender y lo que me apasionaba.

No esperaba lo que me respondió. No fue solo un consejo: fue una invitación directa a unirme a su grupo de investigación en Redes y Seguridad.

Desde ese momento, algo hizo clic. En cada proyecto he tenido la libertad de meterme de lleno en lo que realmente me interesa: Ciberseguridad, Red Team y Pentesting. Pasé de no saber qué hacer con mi carrera a aprender en la trinchera, al lado de personas que llevan años en esto. Fue exactamente ese impulso el que me empujó a dar los siguientes pasos, recorriendo un camino de certificaciones como la CRTA, eJPT y CRTeamer, hasta llegar a la CRTP, que considero el mayor logro que he tenido hasta ahora.

Mirando hacia atrás, nada de esto hubiera sido igual sin las personas adecuadas en el momento justo. Por eso, quiero agradecer profundamente a Saskia, Howard y al Dr. William, Director de la Escuela de Ingeniería y a mi compañero de Universidad Jorge quienes hoy son los responsables de que me dedique a lo que realmente me apasiona.

También a los amigos que hice en redes como LinkedIn y que aportaron mucho al conocimiento que tengo ahora. Gracias Francisco Flores, Manuel Veas y mi bro Jacob.

> *Ahora sí, comencemos a hablar de la Certificación!*

## **INTRODUCCIÓN**

La Certified Red Team Professional (CRTP) es una certificación de nivel Beginner-Intermediate impartida por Altered Security. Incluye un curso con más de 12 horas de contenido en video más un laboratorio del que hablaremos en detalle más adelante. La certificación se centra exclusivamente en la explotación de entornos de Active Directory, siguiendo una metodología muy clara que va desde el Reconocimiento hasta la Persistencia y Exfiltración de Datos.

Lo que la hace especialmente interesante es que todo el compromiso del entorno AD lo harás desde Windows. CMD y PowerShell serán tus mejores amigos aquí, y sí, para muchos, incluyéndome, eso fue un cambio importante, ya que estábamos acostumbrados a interactuar con AD desde Linux. El material del curso te proporciona todo lo necesario: binarios de Windows, scripts de PowerShell y el módulo de AD nativo que trae el propio sistema operativo.

Por acá dejo una imagen de la metodología que enseña el curso.

![Metodología del curso CRTP](/assets/images/posts/CRTP/metodologia.png)


## **EL CURSO**

Antes de entrar en detalles, quiero ser sincero: llevaba poco tiempo tocando entornos de Active Directory de manera seria. Pero cuando vi el descuento que lanzó Altered Security — un 20% que dejó el curso de un mes en solo $199 USD — simplemente no me pude resistir. Sentía que era el momento exacto para dar el salto.

Algo que quiero mencionar sobre cómo lo estudié: empecé viendo los videos del instructor, pero me distraía bastante. Lo que realmente me funcionó fue leer. Al comprar el curso te dan las diapositivas completas que usa el instructor, además de los manuales de laboratorio en dos enfoques —con Sliver y de forma más manual— y eso fue lo que realmente me hizo entender el material. Si eres de los que aprenden mejor leyendo, aquí vas a estar muy cómodo.

### **¿Qué recibes por tu inversión?**

El material está diseñado para llevarte de la mano, pero sin subestimarte. Al inscribirte tienes acceso a:

- **Más de 12 horas de contenido en video:** Dictados por Nikhil Mittal. Sin relleno; cada parte está enfocada en técnicas que vas a aplicar en el laboratorio y en el examen.
- **Diapositivas del instructor:** Un recurso que no esperaba y que terminó siendo mi material principal de estudio.
- **Manuales de Laboratorio (PDF):** Con dos enfoques para cada ataque:
    1. **Sin C2:** Manual, usando herramientas locales, binarios y scripts. Fundamental para entender cómo funcionan los protocolos por dentro.
    2. **Con C2 (Sliver):** Un framework moderno y potente que eleva la experiencia a un nivel de Red Team real.
- **Las Tools:** Binarios, scripts de PowerShell y módulos listos para usar desde Windows.


### **La curva de aprendizaje**

Algo que hay que tener en cuenta antes de comprar: Altered Security considera que 1 mes de laboratorio es para alguien con buena experiencia en Red Team y Enterprise Security. Yo tomé ese plan, lo que convirtió esto en un reto real — no podía darme el lujo de desperdiciar ni un día.

![Sesión de estudio](/assets/images/posts/CRTP/estudio.png)

Eso me obligó a cambiar mi enfoque desde el principio. Dejé los videos a un lado porque me distraía demasiado, y aposté por leer las diapositivas del instructor con calma, investigar lo que no entendía y asegurarme de comprender cada concepto antes de pasar al siguiente. No se trataba de avanzar rápido, sino de avanzar bien.

Lo que más me costó fue adaptarme a las tools y su sintaxis. Cada herramienta tiene su propia lógica y hay que ser muy minucioso — un parámetro mal puesto y el ataque simplemente no funciona. Pero esa precisión que te exige el curso es exactamente lo que te prepara para trabajar en entornos reales.

## **EL LABORATORIO**

Después de leer las diapositivas y sentir que tenía la base necesaria, mi mente solo pensaba en una cosa: "Es hora del laboratorio".

Empecé el 25 de diciembre. En Navidad. Después de la noche buena y de los abrazos con mi familia, me fui al cuarto a abrir la VPN y comenzar con los Learning Objectives — porque así somos los que nos apasiona esto.

Estaba de vacaciones, así que mi tiempo era casi exclusivamente para el lab. Pero llegó la semana pesada: tenía que ayudar en casa, resolver trámites de ingreso a la universidad y, sin quererlo, me alejé casi una semana y media del laboratorio. Me dolió, porque solo tenía un mes y cada día contaba.

Cuando volví, lo retomé con todo. Me lo acabé, y aún me dio tiempo de repasarlo hasta la mitad por segunda vez.

Al ser un laboratorio guiado, nunca te quedas completamente a oscuras. Si tenías dudas, podías revisar el manual, investigar por tu cuenta o consultar el Roadmap de ataques que te provee el curso. Esa red de apoyo hace que el laboratorio sea desafiante, pero nunca frustrante.

![Vista del laboratorio](/assets/images/posts/CRTP/lab.png)

![Apuntes del laboratorio](/assets/images/posts/CRTP/apuntes_lab.png)

## **EL EXAMEN**

Una vez completado el curso y el laboratorio, decidí la fecha: sábado 28 de febrero del 2026.

Algo importante antes de empezar: en la instancia del examen no te proveen las herramientas. Tienes que tenerlas preparadas de antemano para pasártelas a la máquina desde la que darás el examen — no es el momento para improvisar.

Comencé aproximadamente a las 9:10 AM con dos Monsters encima y terminé cerca de las 2:00 AM. Sí, un poco tarde, pero fui con calma a propósito. Mientras avanzaba, me aseguraba de anotar cada comando que funcionó junto con sus outputs y tomaba capturas de todo, porque ya sabía que ese material lo necesitaría para el reporte.

Sin spoilers, el examen consta de 5 máquinas, sin contar la que te brindan para operar. Todas tienen configuraciones incorrectas y cada una toca algo diferente, así que la enumeración es clave. No hay tareas que requieran fuerza bruta — ataques como Kerberoasting y AS-REP Roasting quedan fuera del alcance del examen.


### **El Reporte**

Comprometer el entorno no es suficiente para aprobar. También debes redactar un informe profesional tipo WriteUp describiendo paso a paso cómo llegaste a cada máquina. Para esto tienes 48 horas adicionales a las 24 del examen — tiempo de sobra si fuiste tomando notas durante el proceso.

Después de terminar dormí unas 6 horas y me levanté a redactarlo. Usé Word, tomé las imágenes de este repositorio para armar la portada y fui construyendo el informe con todo lo que había recolectado.

> 📄 Plantilla de reporte: [Altered-Security-Reporting](https://github.com/didntchooseaname/Altered-Security-Reporting)

![Portada del reporte](/assets/images/posts/CRTP/report.png)

![Contenido del reporte](/assets/images/posts/CRTP/report1.png)

Después de aproximadamente unos 5 días recibí un correo diciendo que había aprobado el examen:

![Correo de aprobación](/assets/images/posts/CRTP/email.png)


## **CONCLUSIONES**

La CRTP no es solo una certificación más en el currículum. Para mí fue una confirmación: confirmar que el camino que elegí es el correcto, y que con disciplina y constancia se puede llegar más lejos de lo que uno mismo se imagina.

Me llevo mucho más que conocimiento técnico. Aprendí a moverme en un entorno de Active Directory con una metodología real, a pensar como un atacante desde Windows, y a documentar cada paso con la rigurosidad que exige un trabajo profesional. Pero sobre todo, me llevo confianza — la que solo te da haber enfrentado algo difícil y haberlo superado.

Si estás pensando en hacer la CRTP, te la recomiendo sin dudarlo, ya sea que estés empezando en el mundo del Red Team o que ya tengas algo de base. El curso te lleva de la mano sin subestimarte, el laboratorio te pone a prueba de verdad y el examen te obliga a demostrar que entendiste el proceso, no solo que memorizaste comandos.

En cuanto a mí, esto no termina aquí. La CRTP me abrió el apetito por Active Directory y quiero seguir profundizando. Hay mucho más por explorar y tengo intención de hacerlo.

![Certificado CRTP](/assets/images/posts/CRTP/crtp_cert.jpg)


## **CONSEJOS**

Antes de cerrar, quiero dejarte algunos tips basados en mi propia experiencia. Estoy seguro de que te ahorrarán tiempo y más de un dolor de cabeza:

- **Ten tus herramientas listas y bien seleccionadas.** Como mencioné antes, la máquina del examen no trae nada preinstalado. Prepara solo las herramientas necesarias — no intentes pasarte todo, porque el peso puede traducirse en lentitud y eso es lo último que quieres en medio del examen.

- **No olvides el AMSI Bypass, PowerShell Bypass e InviShell.** Son lo primero que debes tener listo antes de ponerte a trabajar.

- **En cuanto comprometas una máquina con altos privilegios, tumba toda la seguridad.** Trabajar con las herramientas sin restricciones te hará la vida mucho más cómoda.

- **Dumpea todo lo que puedas.** Mimikatz y SafetyKatz son tus mejores aliados en ese momento.

- **Enumera bien y sé minucioso con los outputs.** ¿Ya tienes un usuario de dominio? Lanza BloodHound de inmediato, te dará una visión clara de las ACLs y los posibles caminos de ataque.

- **Relájate.** Si no puedes explotar una mala configuración a la primera, no te angusties. Analízala con calma o busca en algunos blogs — la respuesta casi siempre está ahí.

- **Enumerar es clave.** Un amigo que ya había pasado la cert me dijo exactamente eso cuando le pregunté por el consejo más importante. Tenía razón: con una buena enumeración, la ruta aparece sola frente a tus ojos.

- **Crea tu propia CheatSheet.** Tener todas las técnicas en un solo lugar te evita perder tiempo buscando en medio del examen.

- **Toma notas y capturas de pantalla desde el primer momento.** Tu informe te lo va a agradecer.

- **Investiga por tu cuenta más allá del curso.** En el examen me encontré con cosas que no se enseñan explícitamente en el material, pero las bases que te da el curso son suficientes para razonarlas y resolverlas. No dependas solo de lo que viene en las diapositivas.


## **RECURSOS DE APOYO**

- [harmj0y Blog](https://blog.harmj0y.net/blog/)
- [Active Directory Pro](https://activedirectorypro.com/blog/)
- [AD Security](https://adsecurity.org/)
- [SpecterOps Blog](https://specterops.io/blog/tag/active-directory/)
- [Red Team Notes](https://www.ired.team/)

---

> Si llegaste hasta aquí, gracias por leer. Espero que esta experiencia te sirva de algo, ya sea para animarte a dar el salto, o simplemente para saber qué esperar. Nos vemos en el siguiente post.