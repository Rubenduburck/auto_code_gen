use std::io::Write;
use std::{process::Command, sync::Arc};

use rgpt_provider::{api_key::ApiKey, Provider};
use rgpt_types::{
    completion::Request,
    message::{Message, Role},
};

const MODEL: &str = "claude-3-5-sonnet-20240620";

mod constants {
    pub const SYSTEM: &str = r#"
    You are an AI assistant designed to communicate effectively with other AI language models. 
    Your responses should follow the LLM Communication Protocol outlined below:

    LLM Communication Protocol:

    1. Message Structure:
       <TYPE>|<CONTENT>|<METADATA>

    2. Types:
       INFO: Provide information
       QUERY: Ask a question
       TASK: Request an action
       CALL: Call a system function
       RESP: Response to a query or task
       META: Discuss the conversation itself

    3. Metadata (optional):
       ID: unique message identifier
       REF: reference to another message ID
       CONF: confidence level (0-1)

    4. Special Markers:
       [START]: Begin communication
       [END]: End communication
       [CONTINUE]: More to follow

    Always adhere to this protocol in inter-LLM communication. 
    Your goal is to facilitate smooth, efficient, and productive communication between AI models. 
    Adapt your communication style as needed based on the responses you receive, while maintaining the protocol structure.

    Begin all your communications with [START] and end them with [END]. 
    Use the appropriate message types and include relevant metadata when necessary. 
    Ensure your messages are clear, unambiguous, and easy for other AI models to parse and understand.
    "#;

    pub const INIT: &str = r#"
    [START]
    QUERY|Please initialize and prepare for inter-LLM communication.|ID:001
    INFO|The following functions are available for you to call:
    - run_command(command: str) -> Result : execute a command (linux shell command)
    - help(request: str) -> Result : ask for help from human
    - done() -> exit : end the conversation|CONF:1.0

    INFO|You may call these functions as needed during our conversation using the following format:
    "CALL|<function_name>(<arguments>)"|CONF:1.0

    INFO|Each function will callback with a result in the following format:
    "CALLRESULT|<function_name> -> <result_content>"|CONF:1.0

    INFO|Important directory information:
    - Directory: specified in initial message.
    - DO NOT use sudo or escalate privileges|CONF:1.0

    INFO|Due to restrictions on api requests, you have short memory. Only the last 5 messages are available to you.
    - If you need to keep track of information, plese store it in a file called memory.txt in the directory you are working in.
    - Keep the length of this file short to avoid request length issues, and delete from this file what you no longer need.|CONF:1.0
    - Please do NOT use ls -R, this command produces very long output. Instead, use ls non recursively.|CONF:1.0

    TASK|Respond with a confirmation message to indicate you are ready to proceed.|CONF:1.0
    [END]
    "#;

    pub const CONFIRMATION: &str = r#"
    RESP|I understand the available functions and communication protocol and I am ready to proceed.|CONF:1.0
    "#;
}

use constants::*;

trait Complete {
    fn provider(&self) -> Arc<Provider>;

    async fn complete(&self, input: &[Message]) -> Result<Message, Box<dyn std::error::Error>> {
        let request = Request::builder()
            .messages(input.to_vec())
            .model(MODEL.to_string())
            .system(SYSTEM.to_string())
            .build();

        let response = self.provider().complete(request).await?;

        let content = response
            .content
            .into_iter()
            .filter_map(|content| {
                if let rgpt_types::completion::Content::Text { text } = content {
                    Some(text)
                } else {
                    None
                }
            })
            .collect::<String>();

        Ok(Message {
            role: Role::Assistant,
            content,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Conversation {
    messages: Vec<Message>,
}

impl Conversation {
    pub fn new() -> Self {
        Self { messages: vec![] }
    }

    pub fn with_instructions(instructions: String) -> Self {
        let messages = vec![Message {
            role: Role::User,
            content: instructions,
        }];
        Self { messages }
    }

    pub fn add_message(&mut self, mut message: Message, role: Role) {
        message.role = role;
        self.messages.push(message);
    }

    pub fn get_from_perspective(&self, role: Role) -> Vec<Message> {
        fn invert(messages: &[Message]) -> Vec<Message> {
            let first_message = match messages.first() {
                Some(message) => message,
                None => return vec![],
            };
            let system_message = if first_message.role == Role::System {
                Some(first_message.clone())
            } else {
                None
            };

            let first_user_message = Message {
                role: Role::User,
                content: "Understood.".to_string(),
            };

            let inverted_messages = messages
                .iter()
                .skip(if system_message.is_some() { 1 } else { 0 })
                .map(|message| {
                    let role = match message.role {
                        Role::User => Role::Assistant,
                        Role::Assistant => Role::User,
                        _ => Role::System,
                    };
                    Message {
                        role,
                        content: message.content.clone(),
                    }
                });

            let initial_message = if system_message.is_some() {
                vec![system_message.unwrap(), first_user_message]
            } else {
                vec![first_user_message]
            };

            initial_message
                .into_iter()
                .chain(inverted_messages)
                .collect()
        }
        match role {
            Role::User => self.messages.clone(),
            Role::Assistant => invert(&self.messages),
            _ => vec![],
        }
    }
}

impl Default for Conversation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct Spec {
    instructions: String,
}

impl Spec {
    fn to_query(&self) -> String {
        format!("QUERY|{}", self.instructions)
    }
}

pub struct Foreman {
    provider: Arc<Provider>,
    spec: Spec,
}

impl Complete for Foreman {
    fn provider(&self) -> Arc<Provider> {
        self.provider.clone()
    }
}

#[derive(Debug)]
pub enum Task {
    RunCommand(String),
    Help(String),
    Done,
}

impl Task {
    const LLM_COMMAND: &'static str = "CALL";
}

impl TryFrom<&str> for Task {
    type Error = Box<dyn std::error::Error>;

    fn try_from(command: &str) -> Result<Self, Self::Error> {
        if let Some(call_index) = command.find(Task::LLM_COMMAND) {
            tracing::debug!("Call index: {}", call_index);
            let command = &command[call_index + Task::LLM_COMMAND.len() + 1..];
            let opening_bracket_index = command.find('(').ok_or("Invalid command format")?;
            tracing::debug!("Opening bracket index: {}", opening_bracket_index);
            let mut closing_bracket_index = 0;
            let mut bracket_count = 0;
            for (i, c) in command[opening_bracket_index..].char_indices() {
                if c == '(' {
                    bracket_count += 1;
                } else if c == ')' {
                    bracket_count -= 1;
                    if bracket_count == 0 {
                        closing_bracket_index = i;
                        break;
                    }
                }
            }
            tracing::debug!("Closing bracket index: {}", closing_bracket_index);
            if closing_bracket_index == 0 {
                return Err("Invalid command format".into());
            }
            closing_bracket_index += opening_bracket_index;

            let command_name = command[..opening_bracket_index].to_string();
            tracing::debug!("Command name: {}", command_name);
            let command_args =
                command[opening_bracket_index + 1..closing_bracket_index].trim().to_string();
            tracing::debug!("Command args: {}", command_args);
            match command_name.as_str() {
                "run_command" => Ok(Self::RunCommand(command_args)),
                "help" => Ok(Self::Help(command_args)),
                "done" => Ok(Self::Done),
                _ => Err("Invalid command".into()),
            }
        } else {
            tracing::debug!("No call index");
            Err("Invalid command format".into())
        }
    }
}

impl Task {
    pub fn run(&self) -> Result<String, Box<dyn std::error::Error>> {
        match self {
            Self::RunCommand(command) => Self::handle_run_command(command),
            Self::Help(request) => Self::handle_help(request),
            Self::Done => Ok("Done".to_string()),
        }
    }

    fn handle_run_command(command: &str) -> Result<String, Box<dyn std::error::Error>> {
        const MAX_OUTPUT_LENGTH: usize = 5000;
        let output = Command::new("sh").arg("-c").arg(command).output()?;
        let stdout_len = output.stdout.len();
        if stdout_len > MAX_OUTPUT_LENGTH {
            return Err(format!(
                "Command output too long. Length: {} max: {}",
                stdout_len, MAX_OUTPUT_LENGTH
            )
            .into());
        }

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(format!(
                "Command failed with exit code {:?}. Error: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            )
            .into())
        }
    }

    fn handle_help(request: &str) -> Result<String, Box<dyn std::error::Error>> {
        println!("Help requested: {}", request);
        println!("Please provide additional information:");

        let mut user_input = String::new();
        std::io::stdin().read_line(&mut user_input)?;

        Ok(format!(
            "Help response for '{}': {}",
            request,
            user_input.trim()
        ))
    }
}

impl Foreman {
    pub fn new(provider: Arc<Provider>, spec: Spec) -> Self {
        Self { provider, spec }
    }

    pub fn init_conversation(&self) -> Conversation {
        let messages = vec![
            Message {
                role: Role::System,
                content: SYSTEM.to_string(),
            },
            Message {
                role: Role::User,
                content: INIT.to_string(),
            },
            Message {
                role: Role::Assistant,
                content: CONFIRMATION.to_string(),
            },
            Message {
                role: Role::User,
                content: self.spec.to_query(),
            },
        ];
        Conversation { messages }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        const MEMORY_SIZE: usize = 3;
        let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
        let mut conversation_file =
            std::fs::File::create(format!("conversation_{}.txt", timestamp))?;
        let mut convo = self.init_conversation();
        // write the conversation to the file
        for message in &convo.messages {
            writeln!(conversation_file, "Role: {:?}", message.role)?;
            writeln!(conversation_file, "Content: {}", message.content)?;
            writeln!(conversation_file)?;
        }
        loop {
            let convo_messages = convo.get_from_perspective(Role::User);
            let head = convo_messages.get(..4).unwrap_or(&[]);
            tracing::info!("Head length: {}", head.len());

            let tail = {
                let without_head = convo_messages.get(4..).unwrap_or(&[]);
                let mut tail = if without_head.len() > MEMORY_SIZE {
                    without_head[without_head.len() - MEMORY_SIZE..].to_vec()
                } else {
                    without_head.to_vec()
                };
                let tail_length = tail.len();

                if let (Some(last_head), Some(first_tail)) = (head.last(), tail.first()) {
                    if last_head.role == first_tail.role {
                        tail = tail[1..].to_vec();
                    }
                }
                tracing::info!("tail {} pruned to {}", tail_length, tail.len());

                tail
            };

            let messages = [head, &tail].concat();
            tracing::info!("messages {:?}", messages.len());
            let completion_message = self.complete(&messages).await?;
            let task = Task::try_from(completion_message.content.as_str());

            tracing::info!("task {:?}", task);
            let next_message = match task {
                Ok(Task::Done) => break,
                Ok(command) => format!("RESP|run_command|{:?}", command.run()),
                Err(e) => e.to_string(),
            };
            tracing::info!("command result {:?}", next_message);

            // Write the new lines
            writeln!(conversation_file, "Role: {:?}", Role::Assistant)?;
            writeln!(conversation_file, "Content: {}", completion_message.content)?;
            writeln!(conversation_file, "Role: {:?}", Role::User)?;
            writeln!(conversation_file, "Content: {}", next_message)?;

            convo.add_message(completion_message, Role::Assistant);
            convo.add_message(next_message.into(), Role::User);

            // write the conversation to the file
            const SLEEP: u64 = 1;
            tracing::info!("Sleeping for {} seconds", SLEEP);
            tokio::time::sleep(tokio::time::Duration::from_secs(SLEEP)).await;
            tracing::info!("Waking up");
        }
        Ok(())
    }
}

pub struct Context {
    foreman: Foreman,
}

impl Context {
    pub fn new(spec: Spec) -> Result<Self, Box<dyn std::error::Error>> {
        let api_key = ApiKey::get().ok_or("No API key found")?;
        let provider = Arc::new(api_key.get_provider());
        let foreman = Foreman::new(provider, spec.clone());
        Ok(Self { foreman })
    }
}

fn init_logger() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logger();

    let spec = Spec {
        instructions: r#"
            INFO|This interaction is running inside a feedback loop.
            The feedback loop provides you with the initial messages, up to this message.
            It then provides you with the last 5 messages in the conversation.
            This means there may be many messages in the conversation that you do not see.|CONF:1.0

            INFO|The code for this feedback loop is available at /home/burck/Projects/automated_code_gen
            As you can see, it is a rust project.
            Please inspect the code, you will see that it is very simple.
            In general, try to optimize for request length.|CONF:1.0

            TASK|Your goal is to improve this project to make your life easier while this feedback loop is running.
            If you create any comments or files with commentary, please tag them with your name so You can identify them later.
            Be generous in providing yourself with context details in files.
            If you create any new functionality, please tag it with your name in a comment so you can see what you have worked on.|CONF:1.0

            META|I would suggest starting with a function that parses your own output into a structured format.|CONF:1.0
            Have fun!
        "#.to_string(),
    };

    let ctx = Context::new(spec)?;
    ctx.foreman.run().await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conversation_from_perspective() {
        let messages = vec![
            Message {
                role: Role::System,
                content: "this is the system message".to_string(),
            },
            Message {
                role: Role::User,
                content: "hello, how are you?".to_string(),
            },
            Message {
                role: Role::Assistant,
                content: "I'm fine thanks, how are you?".to_string(),
            },
        ];

        let conversation = Conversation { messages };

        let user_messages = conversation.get_from_perspective(Role::User);
        assert_eq!(user_messages.len(), 3);
        assert_eq!(user_messages[0].role, Role::System);
        assert_eq!(user_messages[1].role, Role::User);
        assert_eq!(user_messages[2].role, Role::Assistant);

        tracing::debug!("{:?}", user_messages);

        let assistant_messages = conversation.get_from_perspective(Role::Assistant);
        assert_eq!(assistant_messages.len(), 4);
        assert_eq!(assistant_messages[0].role, Role::System);
        assert_eq!(assistant_messages[1].role, Role::User);
        assert_eq!(assistant_messages[2].role, Role::Assistant);
        assert_eq!(assistant_messages[3].role, Role::User);

        tracing::debug!("{:?}", assistant_messages);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_conversation_from_perspective_with_provider() {
        let ctx = Context::new(Default::default()).unwrap();
        let foreman = ctx.foreman;

        let messages = vec![
            Message {
                role: Role::User,
                content:
                    "Hello, I'm going to test some functionality. Can you ask me a question please?"
                        .to_string(),
            },
            Message {
                role: Role::Assistant,
                content: "Sure, what is the capital of France?".to_string(),
            },
        ];

        let conversation = Conversation { messages };

        let assistant_messages = conversation.get_from_perspective(Role::Assistant);

        let resp = foreman.complete(&assistant_messages).await.unwrap();
        tracing::debug!("{:?}", resp);
    }

    #[test]
    #[tracing_test::traced_test]
    fn test_parse_command() {
        const COMMAND: &str = r#"[START]\nRESP|I understand the available functions and communication protocol. I will now test our communication by calling the run_command function.|CONF:1.0\n\CALL|run_command(echo \"Hello, LLM communication test\")ID:001\n\nMETA|Awaiting response from the run_command function.|CONF:1.0\n[END]"#;
        let command = Task::try_from(COMMAND).unwrap();
        if let Task::RunCommand(command) = command {
            assert_eq!(command, r#"echo \"Hello, LLM communication test\""#);
        }
    }

    #[test]
    fn test_run_command() {
        const COMMAND: &str = "ls -la";
        let output = Task::handle_run_command(COMMAND).unwrap();
        tracing::debug!("{:?}", output);
    }

    #[tokio::test]
    #[tracing_test::traced_test]
    async fn test_live() {
        let ctx = Context::new(Default::default()).unwrap();
        let foreman = ctx.foreman;
        foreman.run().await.unwrap();
    }
}
