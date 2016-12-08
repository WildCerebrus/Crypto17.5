package button;
import javax.swing.JButton;
import javax.swing.JFileChooser;

import ui.Editor;

public abstract class FileSelectionButton extends JButton{
	
	JFileChooser jfc;
	Editor editor;
	
	public FileSelectionButton(Editor editor){
		super();
		this.editor=editor;
		this.jfc=new JFileChooser();
	}
	
	public JFileChooser getJFC(){
		return this.jfc;
	}
}
