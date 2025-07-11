use thiserror::Error;

// Custom errors for Bitcoin operations
#[derive(Error, Debug)]
pub enum BitcoinError {
    #[error("Invalid transaction format")]
    InvalidTransaction,
    #[error("Invalid script format")]
    InvalidScript,
    #[error("Invalid amount")]
    InvalidAmount,
    #[error("Parse error: {0}")]
    ParseError(String),
}

// Generic Point struct for Bitcoin addresses or coordinates
#[derive(Debug, Clone, PartialEq)]
pub struct Point<T> {
    pub x: T,
    pub y: T,
}

impl<T> Point<T> {
    pub fn new(x: T, y: T) -> Self {
        Point { x, y }
    }
}

// Custom serialization for Bitcoin transaction
pub trait BitcoinSerialize {
    fn serialize(&self) -> Vec<u8>;
}

// Legacy Bitcoin transaction
#[derive(Debug, Clone)]
pub struct LegacyTransaction {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

impl LegacyTransaction {
    pub fn builder() -> LegacyTransactionBuilder {
        LegacyTransactionBuilder::default()
    }
}

// Transaction builder
pub struct LegacyTransactionBuilder {
    pub version: i32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

impl Default for LegacyTransactionBuilder {
    fn default() -> Self {
        LegacyTransactionBuilder {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        }
    }
}

impl LegacyTransactionBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(mut self, version: i32) -> Self {
        self.version = version;
        self
    }

    pub fn add_input(mut self, input: TxInput) -> Self {
        self.inputs.push(input);
        self
    }

    pub fn add_output(mut self, output: TxOutput) -> Self {
        self.outputs.push(output);
        self
    }

    pub fn lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    pub fn build(self) -> LegacyTransaction {
        LegacyTransaction {
            version: self.version,
            inputs: self.inputs,
            outputs: self.outputs,
            lock_time: self.lock_time,
        }
    }
}

// Transaction components
#[derive(Debug, Clone)]
pub struct TxInput {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl TxInput {
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(&self.previous_output.serialize());
        v.extend(&(self.script_sig.len() as u32).to_le_bytes());
        v.extend(&self.script_sig);
        v.extend(&self.sequence.to_le_bytes());
        v
    }
    pub fn parse(data: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if data.len() < 36 + 4 {
            // OutPoint + script_len
            return Err(BitcoinError::InvalidTransaction);
        }
        let (outpoint, outpoint_len) = OutPoint::parse(data)?;
        let script_len_start = outpoint_len;
        let script_len = u32::from_le_bytes([
            data[script_len_start],
            data[script_len_start + 1],
            data[script_len_start + 2],
            data[script_len_start + 3],
        ]) as usize;
        let script_start = script_len_start + 4;
        let script_end = script_start + script_len;
        if data.len() < script_end + 4 {
            return Err(BitcoinError::InvalidTransaction);
        }
        let script_sig = data[script_start..script_end].to_vec();
        let sequence = u32::from_le_bytes([
            data[script_end],
            data[script_end + 1],
            data[script_end + 2],
            data[script_end + 3],
        ]);
        Ok((
            TxInput {
                previous_output: outpoint,
                script_sig,
                sequence,
            },
            script_end + 4,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct TxOutput {
    pub value: u64, // in satoshis
    pub script_pubkey: Vec<u8>,
}

impl TxOutput {
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(&self.value.to_le_bytes());
        v.extend(&(self.script_pubkey.len() as u32).to_le_bytes());
        v.extend(&self.script_pubkey);
        v
    }
    pub fn parse(data: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if data.len() < 8 + 4 {
            return Err(BitcoinError::InvalidTransaction);
        }
        let value = u64::from_le_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);
        let script_len = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let script_start = 12;
        let script_end = script_start + script_len;
        if data.len() < script_end {
            return Err(BitcoinError::InvalidTransaction);
        }
        let script_pubkey = data[script_start..script_end].to_vec();
        Ok((
            TxOutput {
                value,
                script_pubkey,
            },
            script_end,
        ))
    }
}

#[derive(Debug, Clone)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

impl OutPoint {
    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(&self.txid);
        v.extend(&self.vout.to_le_bytes());
        v
    }
    pub fn parse(data: &[u8]) -> Result<(Self, usize), BitcoinError> {
        if data.len() < 32 + 4 {
            return Err(BitcoinError::InvalidTransaction);
        }
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&data[0..32]);
        let vout = u32::from_le_bytes([data[32], data[33], data[34], data[35]]);
        Ok((OutPoint { txid, vout }, 36))
    }
}

// Simple CLI argument parser
// Simple CLI argument parser
pub fn parse_cli_args(args: &[String]) -> Result<CliCommand, BitcoinError> {
    if args.is_empty() {
        return Err(BitcoinError::ParseError("No command provided".to_string()));
    }
    match args[0].as_str() {
        "send" => {
            if args.len() < 3 {
                return Err(BitcoinError::ParseError(
                    "Missing arguments for send".to_string(),
                ));
            }
            let amount = args[1]
                .parse::<u64>()
                .map_err(|_| BitcoinError::InvalidAmount)?;
            let address = args[2].clone();
            Ok(CliCommand::Send { amount, address })
        }
        "balance" => Ok(CliCommand::Balance),
        _ => Err(BitcoinError::ParseError("Unknown command".to_string())),
    }
}

pub enum CliCommand {
    Send { amount: u64, address: String },
    Balance,
}

// Decoding legacy transaction
impl TryFrom<&[u8]> for LegacyTransaction {
    type Error = BitcoinError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // Minimum length: 16 bytes (4 version + 4 inputs count + 4 outputs count + 4 lock_time)
        if data.len() < 16 {
            return Err(BitcoinError::InvalidTransaction);
        }
        let version = i32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let inputs_count = u32::from_le_bytes([data[4], data[5], data[6], data[7]]) as usize;
        let outputs_count = u32::from_le_bytes([data[8], data[9], data[10], data[11]]) as usize;
        let lock_time = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
        let mut offset = 16;
        let mut inputs = Vec::with_capacity(inputs_count);
        for _ in 0..inputs_count {
            let (input, used) = TxInput::parse(&data[offset..])?;
            inputs.push(input);
            offset += used;
        }
        let mut outputs = Vec::with_capacity(outputs_count);
        for _ in 0..outputs_count {
            let (output, used) = TxOutput::parse(&data[offset..])?;
            outputs.push(output);
            offset += used;
        }
        Ok(LegacyTransaction {
            version,
            inputs,
            outputs,
            lock_time,
        })
    }
}

// Custom serialization for transaction
impl BitcoinSerialize for LegacyTransaction {
    fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(&self.version.to_le_bytes());
        v.extend(&(self.inputs.len() as u32).to_le_bytes());
        v.extend(&(self.outputs.len() as u32).to_le_bytes());
        v.extend(&self.lock_time.to_le_bytes());
        for input in &self.inputs {
            v.extend(input.serialize());
        }
        for output in &self.outputs {
            v.extend(output.serialize());
        }
        v
    }
}
