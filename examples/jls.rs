extern crate jail;

#[macro_use]
extern crate prettytable;

use jail::RunningJail;
use prettytable::cell::Cell;
use prettytable::row::Row;
use prettytable::Table;

fn main() {
    let mut table = Table::new();
    table.add_row(row!["JID", "IP Address", "Hostname", "Path"]);

    for j in RunningJail::all() {
        let ips: Vec<String> = j
            .ips()
            .unwrap()
            .iter()
            .map(|ip| format!("{}", ip))
            .collect();

        table.add_row(Row::new(vec![
            Cell::new(&format!("{}", j.jid)),
            Cell::new(&ips.join("\n")),
            Cell::new(&format!("{}", j.hostname().unwrap())),
            Cell::new(j.path().unwrap().to_str().unwrap()),
        ]));
    }

    table.printstd();
}
