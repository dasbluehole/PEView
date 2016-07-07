#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include "exefile.h"
#include <QMainWindow>
#include <QTreeWidgetItem>
#include <QTreeWidget>
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_actionE_Xit_triggered();

    void on_action_Open_triggered();

    void on_treeWidget_itemClicked(QTreeWidgetItem *item, int column);

private:
    void add_root(QString name, QString description);
    void add_child(QTreeWidgetItem *parent,QString name, QString description);
    void add_child(QString parent_name, QString name, QString description);
    QTreeWidgetItem *find_node_by_name(QString name);
    Ui::MainWindow *ui;
    Exefile *exe;
};

#endif // MAINWINDOW_H
