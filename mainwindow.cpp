#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDebug>
#include "exefile.h"
MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    exe = new Exefile;
    ui->treeWidget->setColumnCount(2);
    ui->treeWidget->expandAll();
    ui->treeWidget->setColumnWidth(0,20);
    ui->treeWidget->setColumnWidth(1,100);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionE_Xit_triggered()
{
    qApp->exit(0);
}
void MainWindow::add_root(QString name, QString description)
{
    QTreeWidgetItem *item =new QTreeWidgetItem(ui->treeWidget);
    item->setText(0,name);
    item->setText(1,description);
}
void MainWindow::add_child(QTreeWidgetItem *parent, QString name, QString description)
{
    QTreeWidgetItem *item =new QTreeWidgetItem;
    item->setText(0,name);
    item->setText(1,description);
    parent->addChild(item);
}
void MainWindow::add_child(QString parent_name, QString name, QString description)
{
    QTreeWidgetItem *parent;
    parent = find_node_by_name(parent_name);
    if(!parent)
    {
        qDebug()<<"Error finding parent->"<<parent_name;
        return;
    }
    add_child(parent,name,description);
}

QTreeWidgetItem *MainWindow::find_node_by_name(QString name)
{
    /*QTreeWidgetItem *root=ui->treeWidget->topLevelItem(0);
    qDebug()<<root->childCount()<<root->text(0);*/
    for(int i=0;i < ui->treeWidget->topLevelItemCount();i++)
    {
        if(ui->treeWidget->topLevelItem(i)->text(0)==name)
            return(ui->treeWidget->topLevelItem(i));
        for(int j=0;j<ui->treeWidget->topLevelItem(i)->childCount();j++)
        {
            if(ui->treeWidget->topLevelItem(i)->child(j)->text(0)==name)
                return(ui->treeWidget->topLevelItem(i)->child(j));
        }
    }
    return 0;
}

void MainWindow::on_action_Open_triggered()
{
    // open the file here
    QString filename;
    filename = QFileDialog::getOpenFileName(this,
                                            tr ("Open File"),
                                            ".",
                                            tr ("all files (*)" ));
    if (filename.isEmpty ())
        return;
    exe->set_file(filename);
    if(!exe->is_valid()) // check if a valid EXE file
    {
        QMessageBox::warning(0,"Invalid File","Invalid signature of wrong format file "+filename,QMessageBox::Ok);
        return;
    } // ok we got a valid exefile
    add_root("EXE",filename); // set root node
    add_child("EXE","DOS Header","DOS header of exe file"); // set MZ header as first child node
    // exe info
    QString exeinfostr = exe->exeinfo();
    QStringList tmp=exeinfostr.split("\n");
    foreach (QString s, tmp)
    {
        QStringList t=s.split(':');
        add_child("DOS Header",t.first(),t.last());
    }
    //add_child("EXE","Ext Header", "Extended DOS header");   // set extended dos header as second child
    if(!exe->is_pe_ne())
    {
        QMessageBox::warning(0,"Invalid File","not a PE or NE format file "+filename,QMessageBox::Ok);
        return;
    }
    if(!exe->is_pe())
    {
        QMessageBox::warning(0,"Invalid File","not a PE format file "+filename,QMessageBox::Ok);
        return;
    }
    add_child("EXE","PE Header","PE header of exe file");   // set PE header as 3rd child
    //add_child("EXE","Optional Header", "Optional PE header");// set opt header as 4th child
    // from hear we will add the fields and their values to the tree from structures

    // peinfo
    QString peinfostr = exe->get_pe_info();
    QStringList tmp1=peinfostr.split("\n");
    foreach(QString s,tmp1)
    {
        QStringList t=s.split(':');
        add_child("PE Header",t.first(),t.last());
    }
}

void MainWindow::on_treeWidget_itemClicked(QTreeWidgetItem *item, int column)
{
    // code for item secetion action
    //qDebug()<<"Item"<<item->text(0)<< "in cloumn "<<column<<" is clicked";
}
