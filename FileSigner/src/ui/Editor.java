package ui;
import java.awt.Dimension;
import java.awt.GridLayout;

import javax.swing.JFrame;
import javax.swing.JPanel;

import button.FileSelectionButton;
import button.ToSignButton;
import button.ToVerifyButton;

public class Editor extends JFrame{

	KeyStoreTools kst;
	FileSelectionButton toVerify;
	FileSelectionButton toSign;
	
	public Editor(){
		super("Cryptography Editor");
		
		this.toVerify = new ToVerifyButton(this);
		this.toSign = new ToSignButton(this);
		
		this.addWindowListener(new java.awt.event.WindowAdapter(){
			public void windowClosing(java.awt.event.WindowEvent evt){
				System.exit(0);
			}
		});
		
		JPanel buttonPanel = new JPanel();
		buttonPanel.setLayout(new GridLayout(1, 2));
		buttonPanel.add(this.toSign);
		buttonPanel.add(this.toVerify);
		/*this.setLayout(new GridLayout(1, 2));
		this.setPreferredSize(new Dimension(500,500));
		this.getContentPane().add(this.toSign);
		this.getContentPane().add(this.toVerify);*/
		this.getContentPane().add(buttonPanel);
		this.setPreferredSize(new Dimension(500,500));
	}
	
	public static void main(String[] args) {
		Editor editor = new Editor();
		editor.pack();
		editor.setVisible(true);
		/*JFileChooser chooser = new JFileChooser();
		chooser.showOpenDialog(null);
		System.out.println(chooser.getName(chooser.getSelectedFile()));*/
	}

	public void verify() {
		System.out.println(toVerify.getJFC().getName(toVerify.getJFC().getSelectedFile()));	
	}
}
