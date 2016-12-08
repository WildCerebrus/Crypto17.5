package button;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import ui.Editor;

public class ToVerifyButton extends FileSelectionButton implements MouseListener{
	
	public ToVerifyButton(Editor editor) {
		super(editor);
		this.addMouseListener(this);
		this.setText("VERIFIER");
	}

	@Override
	public void mouseClicked(MouseEvent arg0) {
		System.out.println("Verifier");
		jfc.showOpenDialog(null);
		editor.verify();
	}

	@Override
	public void mouseEntered(MouseEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void mouseExited(MouseEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void mousePressed(MouseEvent arg0) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void mouseReleased(MouseEvent arg0) {
		// TODO Auto-generated method stub
		
	}
}
