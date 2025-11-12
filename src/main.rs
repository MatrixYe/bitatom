mod key;

fn main() {
    println!("Hello, world!");
    let keypair = key::Keypair::new();
    println!("{:?}", keypair);
}
