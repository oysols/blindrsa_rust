use anyhow::Context;
use blind_rsa_signatures as brs;
use pyo3::prelude::*;

#[pyclass]
pub struct PublicKey {
    pub pk: brs::PublicKey,
}

#[pymethods]
impl PublicKey {
    #[new]
    pub fn new(public_key: String) -> PyResult<Self> {
        Ok(PublicKey {
            pk: brs::PublicKey::from_pem(&public_key).context("PublicKey PEM format error")?,
        })
    }
    pub fn blind(
        &self,
        msg: &[u8],
        randomize_message: bool,
    ) -> PyResult<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
        let options = brs::Options::default();
        let blinding_result = self
            .pk
            .blind(&mut brs::DefaultRng, msg, randomize_message, &options)
            .context("Blinding error")?;
        let msg_randomizer: Option<Vec<u8>> = blinding_result
            .msg_randomizer
            .map_or(None, |v| Some(v.to_vec()));
        Ok((
            blinding_result.blind_msg.to_vec(),
            blinding_result.secret.to_vec(),
            msg_randomizer,
        ))
    }

    pub fn finalize(
        &self,
        blind_sig: Vec<u8>,
        secret: &[u8],
        msg_randomizer: Option<&[u8]>,
        msg: &[u8],
    ) -> PyResult<Vec<u8>> {
        let options = brs::Options::default();
        let msg_randomizer = msg_randomizer
            .map(|v| v.try_into().context("MessageRandomizer format error"))
            .transpose()?
            .map(|v| brs::MessageRandomizer(v));
        let sig = self
            .pk
            .finalize(
                &brs::BlindSignature(blind_sig),
                &brs::Secret(secret.into()),
                msg_randomizer,
                msg,
                &options,
            )
            .context("Finalize error")?;
        Ok(sig.to_vec())
    }

    pub fn verify(
        &self,
        sig: Vec<u8>,
        msg: &[u8],
        msg_randomizer: Option<&[u8]>,
    ) -> PyResult<bool> {
        let options = brs::Options::default();
        let msg_randomizer: Option<[u8; 32]> = msg_randomizer
            .map(|v| v.try_into().context("MessageRandomizer format error"))
            .transpose()?;
        let msg_randomizer = msg_randomizer.map(|v| brs::MessageRandomizer(v));
        brs::Signature(sig)
            .verify(&self.pk, msg_randomizer, msg, &options)
            .context("Signature verification error")?;
        Ok(true)
    }
}

#[pyclass]
pub struct SecretKey {
    pub sk: brs::SecretKey,
}

#[pymethods]
impl SecretKey {
    #[new]
    pub fn new(secret_key: String) -> PyResult<Self> {
        Ok(SecretKey {
            sk: brs::SecretKey::from_pem(&secret_key).context("SecretKey PEM format error")?,
        })
    }
    pub fn sign(&self, blind_msg: Vec<u8>) -> PyResult<Vec<u8>> {
        let options = brs::Options::default();
        let blind_sig = self
            .sk
            .blind_sign(&mut brs::DefaultRng, blind_msg, &options)
            .context("Signing error")?;
        Ok(blind_sig.to_vec())
    }
}

#[pymodule]
fn blindrsa_rust(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PublicKey>()?;
    m.add_class::<SecretKey>()?;
    Ok(())
}
