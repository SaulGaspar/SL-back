const assert=require('node:assert/strict');
const nodemailer=require('nodemailer');
const {createTransporter}=require('../helpers/mailer');
async function main(){
 for(const [port,secure] of [['465',true],['587',false],['',false]]){
  process.env.EMAIL_PORT=port;
  const transport=createTransporter();assert.equal(transport.options.port,port?Number(port):587);assert.equal(transport.options.secure,secure);transport.close();
 }
 // Produce el mensaje en memoria, sin contactar un servidor SMTP ni usar credenciales.
 const transport=nodemailer.createTransport({streamTransport:true,buffer:true,newline:'unix'});
 const result=await transport.sendMail({from:'SportLike <no-reply@example.test>',to:'ana@example.test',subject:'Verifica tu correo - SportLike',text:'Mensaje de prueba',html:'<p>Mensaje de prueba</p>'});
 const message=result.message.toString();assert.ok(message.includes('Subject: Verifica tu correo - SportLike'));assert.ok(message.includes('ana@example.test'));assert.ok(message.includes('Mensaje de prueba'));
 transport.close();console.log('CORREO OK: configuración SMTP 465/587 y generación MIME en memoria. No se envió ningún correo real.');
}
main().catch(error=>{console.error(error);process.exitCode=1;});
